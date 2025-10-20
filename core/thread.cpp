#include "thread.h"
#include "injector.h"
#include "N2.hpp"

#include <windows.h>
#include <processsnapshot.h>
#include <inttypes.h>

#include <vector>
#include <algorithm>
#include <optional>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <array>
#include <string>

#pragma comment(lib, "kernel32.lib")

std::optional<DWORD> N2TargetThread(HANDLE hProcess) {
    if (!hProcess) {
        std::puts("Invalid process handle");

        return std::nullopt;
    }

    HPSS snap = nullptr;
    DWORD status = PssCaptureSnapshot(hProcess, PSS_CAPTURE_THREADS, 0, &snap);

    std::printf("PssCaptureSnapshot rc=0x%08lX snap=%p\n", status, (void*)snap);

    if (status != ERROR_SUCCESS || !snap) {
        std::puts("Failed to capture threads");

        return std::nullopt;
    }

    HPSSWALK walk = nullptr;
    status = PssWalkMarkerCreate(nullptr, &walk);
    if (status != ERROR_SUCCESS || !walk) {
        std::printf("PssWalkMarkerCreate rc=0x%08lX\n", status);

        PssFreeSnapshot(GetCurrentProcess(), snap);

        return std::nullopt;
    }

    std::vector<PSS_THREAD_ENTRY> threads;

    for (;;) {
        PSS_THREAD_ENTRY entry{};

        status = PssWalkSnapshot(snap, PSS_WALK_THREADS, walk, &entry, sizeof(entry));

        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status != ERROR_SUCCESS) {
            std::printf("PssWalkSnapshot rc=0x%08lX\n", status);

            PssWalkMarkerFree(walk);
            PssFreeSnapshot(GetCurrentProcess(), snap);

            return std::nullopt;
        }

        // std::printf("TID=%u create=%llu\n", entry.ThreadId, FtToULL(entry.CreateTime));

        threads.push_back(entry);
    }

    std::printf("PssWalkSnapshot complete, %zu threads\n", threads.size());

    PssWalkMarkerFree(walk);

    if (threads.empty()) {
        std::puts("No threads in snapshot");
        PssFreeSnapshot(GetCurrentProcess(), snap);

        return std::nullopt;
    }

    auto mainIt = std::min_element(
        threads.begin(), threads.end(), [](const PSS_THREAD_ENTRY& a, const PSS_THREAD_ENTRY& b) { return FtToULL(a.CreateTime) < FtToULL(b.CreateTime);}
    );

    DWORD mainTid = mainIt->ThreadId;
    std::printf("Main thread = %u\n", mainTid);

    DWORD bestTid = 0;
    unsigned long long bestTime = 0;

    for (const auto& t : threads) {
        if (t.ThreadId == mainTid) continue;

        unsigned long long total = FtToULL(t.UserTime) + FtToULL(t.KernelTime);

        if (total > bestTime) {
            bestTime = total;
            bestTid = t.ThreadId;
        }
    }

    DWORD chosen = bestTid ? bestTid : mainTid;

    std::printf("Targeted thread = %u (cpu=%llu)\n", chosen, bestTime);

    PssFreeSnapshot(GetCurrentProcess(), snap);

    return chosen;
}

class STS {
    HANDLE _hThread;
    bool _suspended;

public:
    explicit STS(HANDLE hThread) : _hThread(hThread), _suspended(false) {
        if (!_hThread) return;

        DWORD rc = SuspendThread(_hThread);

        if (rc == (DWORD)-1)
            throw std::runtime_error("SuspendThread failed");

        _suspended = true;
    }

    ~STS() {
        if (_suspended && _hThread) {
            DWORD rc = ResumeThread(_hThread);
            printf("resumed thread (rc=%lu)\n", rc);
        }
    }

    void detach() noexcept { _suspended = false; }

    STS(const STS&) = delete; STS& operator=(const STS&) = delete;
};

[[noreturn]] static void ThrowWinErr(const char* msg, DWORD err = GetLastError()) {
    char buf[512];
    std::snprintf(buf, sizeof(buf), "%s (err=%lu)", msg, err);
    throw std::runtime_error(buf);
}

static bool IsPageExecutable(DWORD protect) noexcept {
        return
        (protect & PAGE_EXECUTE) ||
        (protect & PAGE_EXECUTE_READ) ||
        (protect & PAGE_EXECUTE_READWRITE) ||
        (protect & PAGE_EXECUTE_WRITECOPY);
}

class RemoteAlloc {
    HANDLE _hProc;
    LPVOID _addr;
    SIZE_T _size;

public:
    RemoteAlloc(HANDLE hProc = nullptr, SIZE_T size = 0, DWORD protect = PAGE_READWRITE)
        : _hProc(hProc), _addr(nullptr), _size(size)
    {
        if (!_hProc || _size == 0) return;

        NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", _hProc, &_addr, 0, &_size, MEM_COMMIT | MEM_RESERVE, protect);

        if (!NT_SUCCESS(st)) ThrowWinErr("NtAllocateVirtualMemory failed");
    }

    ~RemoteAlloc() {
        if (_addr && _hProc) {
            SIZE_T size = 0;
            ab_call_fn_cpp<NTSTATUS>("NtFreeVirtualMemory", _hProc, &_addr, &size, MEM_RELEASE);
        }
    }

    LPVOID release() noexcept {
        LPVOID tmp = _addr;
        _addr = nullptr;
        _size = 0;
        return tmp;
    }

    LPVOID get() const noexcept { return _addr; }
    bool valid() const noexcept { return _addr != nullptr; }

    RemoteAlloc(const RemoteAlloc&) = delete;
    RemoteAlloc& operator=(const RemoteAlloc&) = delete;
    RemoteAlloc(RemoteAlloc&& o) noexcept : _hProc(o._hProc), _addr(o._addr), _size(o._size) {
        o._addr = nullptr; o._size = 0;
    }

    RemoteAlloc& operator=(RemoteAlloc&& o) noexcept {
        if (this != &o) {
            if (_addr && _hProc) {
                SIZE_T size = 0;

                ab_call_fn_cpp<NTSTATUS>("NtFreeVirtualMemory", _hProc, &_addr, &size, MEM_RELEASE);
            }

            _hProc = o._hProc; _addr = o._addr; _size = o._size;
            o._addr = nullptr; o._size = 0;
        }

        return *this;
    }
};

void N2TeleportThreadExecutionLikeJagger(HANDLE hProc, HANDLE hThread, uintptr_t desiredRip) {
    if (!hProc || !hThread) throw std::runtime_error("invalid handles");

    printf("Target process=%p thread=%p desiredRip=%p\n", hProc, hThread, (void*)desiredRip);

    STS suspend(hThread);

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_FLOATING_POINT;

    NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtGetContextThread", hThread, &ctx);
    if (!NT_SUCCESS(st)) ThrowWinErr("NtGetContextThread failed");

    printf("Context: RIP=%p RSP=%p RBP=%p\n", (void*)ctx.Rip, (void*)ctx.Rsp, (void*)ctx.Rbp);

    if (ctx.Rsp < 0x10000 || (ctx.Rsp & 0x7))
        printf("Suspicious RSP alignment or low address %p\n", (void*)ctx.Rsp);

    MEMORY_BASIC_INFORMATION mbiRip{};
    SIZE_T retSize;
    st = ab_call_fn_cpp<NTSTATUS>("NtQueryVirtualMemory", hProc, (PVOID)ctx.Rip, 0, &mbiRip, sizeof(mbiRip), &retSize);
    if (NT_SUCCESS(st)) {
        if (!IsPageExecutable(mbiRip.Protect))
            printf("Old RIP page not executable (Protect=0x%lx)\n", mbiRip.Protect);
    }

    constexpr SIZE_T STACK_FALLBACK_SZ = 0x4000;

    uintptr_t oldRsp = ctx.Rsp;
    uintptr_t chosenRsp = 0;
    uintptr_t retSlot = 0;

    RemoteAlloc remoteStack;

    MEMORY_BASIC_INFORMATION mbiStack{};
    st = ab_call_fn_cpp<NTSTATUS>("NtQueryVirtualMemory", hProc, (PVOID)oldRsp, 0, &mbiStack, sizeof(mbiStack), &retSize);
    if (NT_SUCCESS(st)) {
        printf("Stack region: base=%p size=0x%llx state=0x%lx protect=0x%lx\n",
            mbiStack.BaseAddress, (unsigned long long)mbiStack.RegionSize, mbiStack.State, mbiStack.Protect);

        bool writable = (mbiStack.Protect & PAGE_READWRITE) || (mbiStack.Protect & PAGE_EXECUTE_READWRITE);
        bool guardPage = (mbiStack.Protect & PAGE_GUARD);

        uintptr_t regionBase = (uintptr_t)mbiStack.BaseAddress;
        uintptr_t regionTop = regionBase + (uintptr_t)mbiStack.RegionSize;

        constexpr SIZE_T need = 0x800;

        if (mbiStack.State == MEM_COMMIT && writable && !guardPage && (regionTop - oldRsp) >= need) {
            retSlot = (oldRsp - sizeof(uintptr_t)) & ~static_cast<uintptr_t>(0xF);
            chosenRsp = (retSlot - 0x200) & ~static_cast<uintptr_t>(0xF);
            printf("Using existing stack: retSlot=%p chosenRsp=%p regionTop=%p\n", (void*)retSlot, (void*)chosenRsp, (void*)regionTop);
        }
    }

    if (!chosenRsp) {

        remoteStack = RemoteAlloc(hProc, STACK_FALLBACK_SZ, PAGE_READWRITE);

        if (!remoteStack.valid()) ThrowWinErr("NtAllocateVirtualMemory fallback stack failed");

        uintptr_t stackAddr = reinterpret_cast<uintptr_t>(remoteStack.get());
        if (stackAddr >= 0x80000000) {
            printf("High stack detected %p - retrying low...\n", (void*)stackAddr);

            PVOID lowStackHint = (PVOID)0x10000000;
            SIZE_T lowStackSize = STACK_FALLBACK_SZ;
            st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc, &lowStackHint,
                (ULONG_PTR)0x10000000, &lowStackSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(st) && lowStackHint) {
                remoteStack = RemoteAlloc(hProc, 0, PAGE_READWRITE); // Reassign
                printf("Low stack allocated at %p\n", lowStackHint);
                stackAddr = reinterpret_cast<uintptr_t>(lowStackHint);
            }
        }

        uintptr_t top = stackAddr + STACK_FALLBACK_SZ;

        retSlot = (top - sizeof(uintptr_t)) & ~static_cast<uintptr_t>(0xF);
        chosenRsp = (retSlot - 0x200) & ~static_cast<uintptr_t>(0xF);

        printf("Allocated remote stack at %p (chosenRsp=%p retSlot=%p) %s\n",
            (void*)stackAddr, (void*)chosenRsp, (void*)retSlot,
            stackAddr < 0x80000000 ? "(LOW)" : "(HIGH)");
    }

    {
        uint8_t probeVal = 0xAA;
        SIZE_T wrote = 0;
        st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc, (PVOID)chosenRsp, &probeVal, 1, &wrote);
        if (!NT_SUCCESS(st) || wrote != 1) {
            ThrowWinErr("NtWriteVirtualMemory probe on chosenRsp failed");
        }

        uint8_t zero = 0;

        ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc, (PVOID)chosenRsp, &zero, 1, nullptr);
    }

    if (!retSlot) {
        retSlot = (chosenRsp + 0x1000) & ~static_cast<uintptr_t>(0xF);
    }

    uintptr_t oldRip = ctx.Rip;
    uintptr_t alignedRsp = (chosenRsp & ~static_cast<uintptr_t>(0xFULL));
    alignedRsp = (alignedRsp - 8) & ~static_cast<uintptr_t>(0xFULL);

    auto trampoline = make_trampoline_bytes(static_cast<uint64_t>(oldRip), static_cast<uint64_t>(alignedRsp), static_cast<uint64_t>(desiredRip));

    SIZE_T codeSize = trampoline.size();

    LPVOID trampAddr = nullptr;
    SIZE_T allocSize = codeSize;

    PVOID lowTrampHint = (PVOID)0x20000000;
    SIZE_T lowTrampSize = allocSize;

    st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc, &trampAddr, (ULONG_PTR)lowTrampHint, &lowTrampSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(st)) {
        trampAddr = nullptr;
        allocSize = codeSize;

        st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc, &trampAddr, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!NT_SUCCESS(st)) ThrowWinErr("NtAllocateVirtualMemory(RW) failed");

    printf("RW allocated at %p (%s low memory)\n", trampAddr,
        (uintptr_t)trampAddr < 0x80000000 ? "OK" : "HIGH");

    SIZE_T written = 0;
    st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc, trampAddr, trampoline.data(), codeSize, &written);
    if (!NT_SUCCESS(st) || written != codeSize) {
        SIZE_T zeroSize = 0;

        ab_call_fn_cpp<NTSTATUS>("NtFreeVirtualMemory", hProc, &trampAddr, &zeroSize, MEM_RELEASE);

        ThrowWinErr("NtWriteVirtualMemory(trampoline) failed");
    }

    ULONG oldProtect;

    st = ab_call_fn_cpp<NTSTATUS>("NtProtectVirtualMemory", hProc, &trampAddr, &allocSize, PAGE_EXECUTE_READ, &oldProtect);

    if (!NT_SUCCESS(st)) {
        printf("NtProtectVirtualMemory to RX failed: 0x%X, continuing with RW\n", st);
    }

    st = ab_call_fn_cpp<NTSTATUS>("NtFlushInstructionCache", hProc, trampAddr, codeSize);
    if (!NT_SUCCESS(st)) printf("NtFlushInstructionCache failed: 0x%X\n", st);

    printf("Final=%p size=%zu oldRip=%p alignedRsp=%p desiredRip=%p\n",
        trampAddr, codeSize, (void*)oldRip, (void*)alignedRsp, (void*)desiredRip);

    if (!N2ValidateRemoteExecution(hProc, alignedRsp, reinterpret_cast<uintptr_t>(trampAddr), codeSize)) {
        printf("Execution validation FAILED - aborting resume\n");
        suspend.detach();
        return;
    }

    ctx.Rip = reinterpret_cast<uintptr_t>(trampAddr);
    ctx.Rsp = alignedRsp;

    st = ab_call_fn_cpp<NTSTATUS>("NtSetContextThread", hThread, &ctx);
    if (!NT_SUCCESS(st)) ThrowWinErr("NtSetContextThread failed");

    ab_call_fn_cpp<NTSTATUS>("NtFlushInstructionCache", hProc, nullptr, 0);

    ULONG rc;
    st = ab_call_fn_cpp<NTSTATUS>("NtResumeThread", hThread, &rc);
    if (!NT_SUCCESS(st)) ThrowWinErr("NtResumeThread failed");

    suspend.detach();

    printf("NtResumeThread returned previous suspend count=%lu\n", rc);
    printf("Trampoline at %p and stack candidate at %p left allocated for thread use.\n", trampAddr, (void*)alignedRsp);
}