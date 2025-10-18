#pragma once

#include <windows.h>

#include <vector>
#include <cstddef>

std::vector<BYTE> N2GenShell(
    PVOID   hookAddr,
    PVOID   dllPathAddr,
    PVOID   shellcodeAddr,
    const BYTE* origBytes,
    size_t  hookSize,
    bool    validOrigBytes
);