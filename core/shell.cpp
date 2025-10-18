#include "shell.h"

std::vector<BYTE> N2GenShell(PVOID hookAddr, PVOID dllPathAddr, PVOID shellcodeAddr, const BYTE* origBytes, size_t hookSize, bool validOrigBytes) {

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

    std::vector<BYTE> rs;

    // push
    rs.insert(rs.end(), {
        0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57
        });

    // mov rcx, dllPathAddr
    rs.insert(rs.end(), { 0x48, 0xB9 });
    rs.insert(rs.end(), (BYTE*)&dllPathAddr, (BYTE*)&dllPathAddr + sizeof(PVOID));

    // call LoadLibraryA
    rs.insert(rs.end(), { 0x48, 0xB8 });
    rs.insert(rs.end(), (BYTE*)&loadLibAddr, (BYTE*)&loadLibAddr + sizeof(PVOID));
    rs.insert(rs.end(), { 0xFF, 0xD0 });

    // restore original bytes (only if valid)
    if (validOrigBytes) {
        // mov rcx, hookAddr
        rs.insert(rs.end(), { 0x48, 0xB9 });
        rs.insert(rs.end(), (BYTE*)&hookAddr, (BYTE*)&hookAddr + sizeof(PVOID));

        // mov rsi, origBytesAddr
        rs.insert(rs.end(), { 0x48, 0xBE });
        PVOID origBytesAddr = (PVOID)((BYTE*)shellcodeAddr + rs.size() + 10 + hookSize);
        rs.insert(rs.end(), (BYTE*)&origBytesAddr, (BYTE*)&origBytesAddr + sizeof(PVOID));

        // mov r8, hookSize
        rs.insert(rs.end(), { 0x4C, 0xB8 });
        rs.insert(rs.end(), (BYTE*)&hookSize, (BYTE*)&hookSize + sizeof(size_t));

        // memcpy loop (rep movsb)
        rs.insert(rs.end(), { 0xF3, 0xA4 });
    }

    // pop
    rs.insert(rs.end(), {
        0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58
        });

    // jmp hookAddr + hookSize
    PVOID returnAddr = (PBYTE)hookAddr + hookSize;

    rs.insert(rs.end(), { 0x48, 0xB8 });
    rs.insert(rs.end(), (BYTE*)&returnAddr, (BYTE*)&returnAddr + sizeof(PVOID));
    rs.insert(rs.end(), { 0xFF, 0xE0 });

    if (validOrigBytes) {
        rs.insert(rs.end(), origBytes, origBytes + hookSize);
    }

    printf("Shellcode size: %zu bytes\n", rs.size());

    return rs;
}