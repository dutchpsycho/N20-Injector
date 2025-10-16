#pragma once

// shellcode_gen.h
// Generates x64 shellcode to LoadLibraryA(dllPath), restore original hooked bytes, and jump back.

#include <windows.h>   // for PVOID, FARPROC, BYTE
#include <vector>      // for std::vector
#include <cstddef>     // for size_t

/// GenerateShellcode
/// @param hookAddr        Address of the original hook location (e.g. Sleep)
/// @param dllPathAddr     Remote pointer to the null-terminated DLL path string
/// @param shellcodeAddr   Base address where this shellcode will be written
/// @param origBytes       Pointer to the original bytes overwritten by the hook
/// @param hookSize        Number of bytes overwritten by the hook (e.g. 12)
/// @param validOrigBytes  True if origBytes are valid and should be restored
/// @returns               A byte vector containing the complete shellcode (with optional origBytes appended)
std::vector<BYTE> GenerateShellcode(
    PVOID   hookAddr,
    PVOID   dllPathAddr,
    PVOID   shellcodeAddr,
    const BYTE* origBytes,
    size_t  hookSize,
    bool    validOrigBytes
);