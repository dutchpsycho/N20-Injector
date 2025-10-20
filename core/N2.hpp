#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#include <cstdio>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <algorithm>
#include <optional>
#include <cstdint>

#include "../dependency/ActiveBreach-Engine/C++/Include/ActiveBreach.hpp"

#pragma comment(lib, "Shlwapi.lib")

using std::string;
using std::string_view;
using std::vector;
using std::array;
using std::optional;

using byte = unsigned char;
using NTSTATUS = LONG;

static auto NT_SUCCESS = [](NTSTATUS st) { return st >= 0; };

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

bool N2ValidateRemoteExecution(HANDLE hProc, uintptr_t stackAddr, uintptr_t trampAddr, size_t trampSize);
string N2ResolveDllPath(string_view dllName);
string N2FindSystemDllPath32(string_view dllName);
optional<uintptr_t> N2GetRemoteModuleBase(DWORD pid, string_view moduleName);
optional<uintptr_t> N2GetExportRVA(string_view dllPath, string_view exportName);
optional<PVOID> N2ResolveRemoteProc(DWORD pid, string_view dllName, string_view apiName);

inline unsigned long long FtToULL(const FILETIME& ft) {
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static inline void append_u64_le(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

static inline std::vector<uint8_t> make_trampoline_bytes(uint64_t oldRip, uint64_t newRsp, uint64_t desiredRip) {
    std::vector<uint8_t> code;

    // mov rax, oldRip
    code.push_back(0x48); code.push_back(0xB8); append_u64_le(code, oldRip);

    // mov rsp, newRsp  
    code.push_back(0x48); code.push_back(0xBC); append_u64_le(code, newRsp);

    // push rax
    code.push_back(0x50);

    // mov r10, desiredRip
    code.push_back(0x49); code.push_back(0xBA); append_u64_le(code, desiredRip);

    // jmp r10
    code.push_back(0x41); code.push_back(0xFF); code.push_back(0xE2);

    return code;
}