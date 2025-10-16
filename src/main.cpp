#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <shlwapi.h>
#include "../extern/ActiveBreach-Engine/C++/Include/ActiveBreach.hpp"
#include "injector.h"

// NTSTATUS and NT_SUCCESS
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

// SystemProcessInformation class
#define SystemProcessInformation 5
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

// NtQuerySystemInformation typedef
typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG);

// This matches the real layout (so ImageName and UniqueProcessId are in the right spot)
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved1;
    LARGE_INTEGER Reserved2;
    LARGE_INTEGER Reserved3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    SIZE_T   PeakVirtualSize;
    SIZE_T   VirtualSize;
    ULONG    HandleCount;
    ULONG    SessionId;
    SIZE_T   PeakWorkingSetSize;
    SIZE_T   WorkingSetSize;
    SIZE_T   QuotaPeakPagedPoolUsage;
    SIZE_T   QuotaPagedPoolUsage;
    SIZE_T   QuotaPeakNonPagedPoolUsage;
    SIZE_T   QuotaNonPagedPoolUsage;
    SIZE_T   PagefileUsage;
    SIZE_T   PeakPagefileUsage;
    SIZE_T   PrivatePageCount;
    // followed by an array of THREAD_INFO structs...
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

static DWORD GetPidByName(const wchar_t* targetName) {
    ULONG    bufferSize = 0x10000;
    PVOID    buffer = nullptr;
    NTSTATUS status;
    auto     NtQSI = (NtQuerySystemInformation_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation");

    if (!NtQSI) {
        printf("Could not find NtQuerySystemInformation\n");
        return 0;
    }

    // 1) Grow buffer until it fits
    do {
        free(buffer);
        buffer = malloc(bufferSize);
        if (!buffer) {
            printf("OOM allocating %lu bytes\n", bufferSize);
            return 0;
        }
        status = ab_call(NtQuerySystemInformation_t,
            "NtQuerySystemInformation",
            SystemProcessInformation,
            buffer, bufferSize, &bufferSize);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        printf("NtQuerySystemInformation failed: 0x%X\n", status);
        free(buffer);
        return 0;
    }

    // 2) Walk the list
    PSYSTEM_PROCESS_INFORMATION proc = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (true) {
        if (proc->ImageName.Buffer &&
            _wcsicmp(proc->ImageName.Buffer, targetName) == 0)
        {
            DWORD pid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;
            free(buffer);
            return pid;
        }
        if (proc->NextEntryOffset == 0)
            break;
        proc = (PSYSTEM_PROCESS_INFORMATION)
            ((BYTE*)proc + proc->NextEntryOffset);
    }

    free(buffer);
    return 0;
}

int main() {
    // 0) Init ActiveBreach
    ActiveBreach_launch();

    // 1) Find Notepad
    const wchar_t* targetExe = L"notepad.exe";
    printf("Looking for %ws...\n", targetExe);
    DWORD pid = GetPidByName(targetExe);
    if (!pid) {
        printf("Error: %ws not found.\n", targetExe);
        return 1;
    }
    printf("Found %ws PID %lu\n", targetExe, pid);

    // 2) Inject
    const char* dllToLoad = "lacerate.dll";
    // Provide the hook target: kernel32.dll!Sleep
    if (!InjectDll(pid, "kernel32.dll", "Sleep", dllToLoad)) {
        printf("Injection failed\n");
        return 1;
    }

    printf("Injection succeeded\n");
    return 0;
}