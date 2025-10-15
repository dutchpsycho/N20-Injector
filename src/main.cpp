#include <windows.h>
#include <string>
#include <shlwapi.h>
#include <vector>
#include "config.h"
#include "../extern/ActiveBreach-Engine/C++/Include/ActiveBreach.hpp"

#pragma comment(lib, "Shlwapi.lib")

// NTSTATUS and NT_SUCCESS
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// SystemProcessInformation
#define SystemProcessInformation 5

// ActiveBreach NT typedefs
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);

// Struct for process info
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// Enable SeDebugPrivilege
bool EnableSeDebugPrivilege() {
    printf("Enabling SeDebugPrivilege...\n");
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed: %lu\n", GetLastError());
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    printf("SeDebugPrivilege enabled\n");
    return true;
}

// Find VLKYR.exe PID
DWORD ScopePID(const wchar_t* targetName) {
    printf("Searching for %ws PID...\n", targetName);
    ULONG size = 0x10000;
    PVOID buffer = malloc(size);
    if (!buffer) {
        printf("Failed to allocate buffer\n");
        return 0;
    }

    NTSTATUS status;
    while ((status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", SystemProcessInformation, buffer, size, &size)) == 0xC0000004) {
        printf("Buffer too small, reallocating to %lu bytes\n", size);
        free(buffer);
        buffer = malloc(size);
        if (!buffer) {
            printf("Failed to reallocate buffer\n");
            return 0;
        }
    }

    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed: 0x%X\n", status);
        free(buffer);
        return 0;
    }

    PSYSTEM_PROCESS_INFORMATION proc = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (proc->NextEntryOffset) {
        if (proc->ImageName.Buffer && _wcsicmp(proc->ImageName.Buffer, targetName) == 0) {
            DWORD pid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;
            free(buffer);
            printf("Found %ws PID: %lu\n", targetName, pid);
            return pid;
        }
        proc = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)proc + proc->NextEntryOffset);
    }

    free(buffer);
    printf("%ws not found\n", targetName);
    return 0;
}

// Resolve DLL path relative to executable
std::string GetLocalDllPath(const char* dllName) {
    printf("Resolving path for %s...\n", dllName);
    char path[MAX_PATH];
    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
        printf("GetModuleFileNameA failed: %lu\n", GetLastError());
        return "";
    }
    PathRemoveFileSpecA(path);
    std::string fullPath = std::string(path) + "\\" + dllName;
    printf("Resolved DLL path: %s\n", fullPath.c_str());
    return fullPath;
}

// Dump shellcode or bytes as hex
void DumpHex(const BYTE* data, size_t size, const char* label) {
    printf("%s (%zu bytes):\n", label, size);
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

// Validate original bytes
bool ValidateOrigBytes(const BYTE* origBytes, size_t hookSize) {
    bool allCC = true;
    for (size_t i = 0; i < hookSize; ++i) {
        if (origBytes[i] != 0xCC) {
            allCC = false;
            break;
        }
    }
    if (allCC || (origBytes[0] == 0x48 && origBytes[1] == 0xFF && origBytes[2] == 0x25)) {
        printf("Warning: origBytes appear invalid (all CC or jmp rel32), possible EDR hook\n");
        return false;
    }
    return true;
}

// Generate x64 shellcode: LoadLibraryA(dllPath), restore original bytes, jump back
std::vector<BYTE> GenerateShellcode(PVOID hookAddr, PVOID dllPathAddr, PVOID shellcodeAddr, const BYTE* origBytes, size_t hookSize, bool validOrigBytes) {
    printf("Generating shellcode...\n");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        hKernel32 = LoadLibraryA("kernel32.dll");
        if (!hKernel32) {
            printf("GetModuleHandleA/LoadLibraryA for kernel32.dll failed: %lu\n", GetLastError());
            return {};
        }
    }
    FARPROC loadLibAddr = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLibAddr) {
        printf("GetProcAddress for LoadLibraryA failed: %lu\n", GetLastError());
        return {};
    }

    // Shellcode: save regs, call LoadLibraryA, restore original bytes (if valid), jump back
    std::vector<BYTE> shellcode;
    // Push registers
    shellcode.insert(shellcode.end(), {
        0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
        });

    // mov rcx, dllPathAddr
    shellcode.insert(shellcode.end(), { 0x48, 0xB9 });
    shellcode.insert(shellcode.end(), (BYTE*)&dllPathAddr, (BYTE*)&dllPathAddr + sizeof(PVOID));

    // call LoadLibraryA
    shellcode.insert(shellcode.end(), { 0x48, 0xB8 });
    shellcode.insert(shellcode.end(), (BYTE*)&loadLibAddr, (BYTE*)&loadLibAddr + sizeof(PVOID));
    shellcode.insert(shellcode.end(), { 0xFF, 0xD0 });

    // Restore original bytes (only if valid)
    if (validOrigBytes) {
        // mov rcx, hookAddr
        shellcode.insert(shellcode.end(), { 0x48, 0xB9 });
        shellcode.insert(shellcode.end(), (BYTE*)&hookAddr, (BYTE*)&hookAddr + sizeof(PVOID));

        // mov rsi, origBytesAddr
        shellcode.insert(shellcode.end(), { 0x48, 0xBE });
        PVOID origBytesAddr = (PVOID)((BYTE*)shellcodeAddr + shellcode.size() + 10 + hookSize);
        shellcode.insert(shellcode.end(), (BYTE*)&origBytesAddr, (BYTE*)&origBytesAddr + sizeof(PVOID));

        // mov r8, hookSize
        shellcode.insert(shellcode.end(), { 0x4C, 0xB8 });
        shellcode.insert(shellcode.end(), (BYTE*)&hookSize, (BYTE*)&hookSize + sizeof(size_t));

        // memcpy loop (rep movsb)
        shellcode.insert(shellcode.end(), { 0xF3, 0xA4 });
    }

    // Pop registers
    shellcode.insert(shellcode.end(), {
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58
        });

    // jmp hookAddr + hookSize
    PVOID returnAddr = (PBYTE)hookAddr + hookSize;
    shellcode.insert(shellcode.end(), { 0x48, 0xB8 });
    shellcode.insert(shellcode.end(), (BYTE*)&returnAddr, (BYTE*)&returnAddr + sizeof(PVOID));
    shellcode.insert(shellcode.end(), { 0xFF, 0xE0 });

    // Append origBytes (only if valid)
    if (validOrigBytes) {
        shellcode.insert(shellcode.end(), origBytes, origBytes + hookSize);
    }

    printf("Shellcode size: %zu bytes\n", shellcode.size());
    DumpHex(shellcode.data(), shellcode.size(), "Shellcode hex dump");
    return shellcode;
}

int main() {
    printf("Initializing ActiveBreach...\n");
    ActiveBreach_launch();
    if (_AbViolationCount()) {
        printf("ActiveBreach violations detected: %u\n", _AbViolationCount());
        return 1;
    }

    if (!EnableSeDebugPrivilege()) {
        printf("Failed to enable SeDebugPrivilege\n");
        return 1;
    }

    DWORD pid = ScopePID(L"robloxplayerbeta.exe");
    if (!pid) {
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, pid);
    if (!hProcess) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Opened process handle: 0x%p\n", hProcess);

    // Get remote kernel32 base and Sleep address
    HMODULE hKernel32Local = GetModuleHandleA("kernel32.dll");
    if (!hKernel32Local) {
        hKernel32Local = LoadLibraryA("kernel32.dll");
        if (!hKernel32Local) {
            printf("GetModuleHandleA/LoadLibraryA for kernel32.dll failed: %lu\n", GetLastError());
            CloseHandle(hProcess);
            return 1;
        }
    }

    PVOID localFuncAddr = (PVOID)GetProcAddress(hKernel32Local, "Sleep");
    if (!localFuncAddr) {
        printf("GetProcAddress for Sleep failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    PVOID remoteFuncAddr = localFuncAddr; // Assume same address space
    printf("Remote Sleep at: 0x%p\n", remoteFuncAddr);

    // Read original bytes
    const size_t hookSize = 12;
    BYTE origBytes[hookSize] = { 0 };
    NTSTATUS status = ab_call(NtReadVirtualMemory_t, "NtReadVirtualMemory", hProcess, remoteFuncAddr, origBytes, (ULONG)hookSize, NULL);
    if (!NT_SUCCESS(status)) {
        printf("NtReadVirtualMemory failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("Read %zu original bytes from 0x%p\n", hookSize, remoteFuncAddr);
    DumpHex(origBytes, hookSize, "Original Sleep bytes");

    // Validate original bytes
    bool validOrigBytes = ValidateOrigBytes(origBytes, hookSize);
    if (!validOrigBytes) {
        printf("Using minimal shellcode without restoration to avoid crash\n");
    }

    // Allocate for DLL path
    std::string dllPath = GetLocalDllPath("lacerate.dll");
    if (dllPath.empty()) {
        CloseHandle(hProcess);
        return 1;
    }
    SIZE_T dllLen = dllPath.length() + 1;
    PVOID dllPathAddr = nullptr;
    SIZE_T regionSize = dllLen;
    status = ab_call(NtAllocateVirtualMemory_t, "NtAllocateVirtualMemory", hProcess, &dllPathAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("NtAllocateVirtualMemory (path) failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    status = ab_call(NtWriteVirtualMemory_t, "NtWriteVirtualMemory", hProcess, dllPathAddr, (PVOID)dllPath.c_str(), (ULONG)dllLen, NULL);
    if (!NT_SUCCESS(status)) {
        printf("NtWriteVirtualMemory (path) failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("DLL path allocated at: 0x%p\n", dllPathAddr);

    // Allocate for shellcode
    PVOID shellcodeAddr = nullptr;
    regionSize = 1024;
    status = ab_call(NtAllocateVirtualMemory_t, "NtAllocateVirtualMemory", hProcess, &shellcodeAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("NtAllocateVirtualMemory (shellcode) failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("Shellcode allocated at: 0x%p\n", shellcodeAddr);

    // Generate shellcode
    std::vector<BYTE> shellcode = GenerateShellcode(remoteFuncAddr, dllPathAddr, shellcodeAddr, origBytes, hookSize, validOrigBytes);
    if (shellcode.empty()) {
        printf("Failed to generate shellcode\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Write shellcode
    status = ab_call(NtWriteVirtualMemory_t, "NtWriteVirtualMemory", hProcess, shellcodeAddr, shellcode.data(), (ULONG)shellcode.size(), NULL);
    if (!NT_SUCCESS(status)) {
        printf("NtWriteVirtualMemory (shellcode) failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("Shellcode written, size: %zu bytes\n", shellcode.size());

    // Change protection of hook location
    regionSize = hookSize;
    ULONG oldProtect = 0;
    PVOID protectAddr = remoteFuncAddr;
    status = ab_call(NtProtectVirtualMemory_t, "NtProtectVirtualMemory", hProcess, &protectAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!NT_SUCCESS(status)) {
        printf("NtProtectVirtualMemory failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("Changed protection of 0x%p to PAGE_EXECUTE_READWRITE (old: 0x%X)\n", remoteFuncAddr, oldProtect);

    // Write hook: jmp to shellcode
    BYTE hookJmp[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, shellcodeAddr
        0xFF, 0xE0                                                 // jmp rax
    };
    memcpy(hookJmp + 2, &shellcodeAddr, sizeof(PVOID));
    status = ab_call(NtWriteVirtualMemory_t, "NtWriteVirtualMemory", hProcess, remoteFuncAddr, hookJmp, hookSize, NULL);
    if (!NT_SUCCESS(status)) {
        printf("NtWriteVirtualMemory (hook) failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("Hook installed at 0x%p\n", remoteFuncAddr);

    // Restore protection
    status = ab_call(NtProtectVirtualMemory_t, "NtProtectVirtualMemory", hProcess, &protectAddr, &regionSize, oldProtect, &oldProtect);
    if (!NT_SUCCESS(status)) {
        printf("Restoring protection failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("Restored protection at 0x%p to 0x%X\n", protectAddr, oldProtect);

#if CR_REMOTE_THREAD_EXECUTION
    // Inject test thread to call Sleep
    PVOID sleepAddr = remoteFuncAddr;
    HANDLE hThread = NULL;
    status = ab_call(NtCreateThreadEx_t, "NtCreateThreadEx", &hThread, THREAD_ALL_ACCESS, NULL, hProcess, sleepAddr, (PVOID)1000, 0, 0, 0, 0, NULL);
    if (NT_SUCCESS(status)) {
        printf("Test thread created to call Sleep\n");
        WaitForSingleObject(hThread, 10000); // Wait 10 seconds for MessageBox
        ab_call(NtClose_t, "NtClose", hThread);
    }
    else {
        printf("NtCreateThreadEx failed: 0x%X\n", status);
    }
#else
    printf("No test thread created (CR_REMOTE_THREAD_EXECUTION = 0). Interact with VLKYR (type, resize, minimize) to trigger Sleep.\n");
#endif

    printf("Threadless hook injection complete. Shellcode executes once on Sleep call, loads DLL, restores original, jumps back.\n");
    CloseHandle(hProcess);
    return 0;
}