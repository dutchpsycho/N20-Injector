#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <iostream>

#include "injector.h"

#include "../extern/ActiveBreach-Engine/C++/Include/ActiveBreach.hpp"

DWORD PID(const wchar_t* targetExe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry = { 0 };
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, targetExe) == 0) {
                CloseHandle(snap);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return 0;
}

int main() {
    LARGE_INTEGER freq = {}, start = {}, end = {};
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    ActiveBreach_launch();

    QueryPerformanceCounter(&end);
    double elms = (end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    printf("[ABE] Init time: %.3f ms\n", elms);

    const wchar_t* target = L"notepad.exe";

    DWORD pid = PID(target);
    if (!pid) {
        printf("Error: %ws not found.\n", target);
        return 1;
    }

    printf("Found %ws PID %lu\n", target, pid);

	const char* dllToLoad = "example.dll"; // replace with your dll path

	if (!N2Inject(pid, "kernel32.dll", "Sleep", dllToLoad)) { // function name can be any exported function
        printf("Injection failed\n");
        return 1;
    }

    printf("Injection succeeded\n");

    return 0;
}
