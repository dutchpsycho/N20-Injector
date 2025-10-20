#include "N2.hpp"

bool N2ValidateRemoteExecution(HANDLE hProc, uintptr_t stackAddr, uintptr_t trampAddr, size_t trampSize) {

    bool stackLowMem = (stackAddr != 0 && stackAddr < 0x80000000);
    bool trampLowMem = (trampAddr < 0x80000000);

    if (stackAddr != 0) {
        MEMORY_BASIC_INFORMATION mbiStack{};
        SIZE_T retSize;
        NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtQueryVirtualMemory", hProc, (PVOID)stackAddr, 0, &mbiStack, sizeof(mbiStack), &retSize);
        if (!NT_SUCCESS(st)) {
            printf("Stack query failed: 0x%X\n", st);
            return false;
        }

        bool stackValid = (mbiStack.State == MEM_COMMIT) && ((mbiStack.Protect & PAGE_READWRITE) || (mbiStack.Protect & PAGE_EXECUTE_READWRITE)) && !(mbiStack.Protect & PAGE_GUARD) && !(mbiStack.Protect & PAGE_NOACCESS);

        printf("Stack[%p]: State=0x%lx Protect=0x%lx %s %s\n",
            (void*)stackAddr, mbiStack.State, mbiStack.Protect, stackValid ? "OK" : "FAIL",
            stackLowMem ? "(LOW)" : "(HIGH - ActiveBreach RISK!)");

        if (!stackValid) {
            printf("Stack protections invalid\n");
            return false;
        }

        uintptr_t regionTop = (uintptr_t)mbiStack.BaseAddress + mbiStack.RegionSize;
        uintptr_t spaceLeft = regionTop - stackAddr;

        bool spaceOK = spaceLeft >= 0x800;

        printf("Stack space left: 0x%zx %s\n", spaceLeft, spaceOK ? "OK" : "FAIL");

        if (!spaceOK) {
            printf("Insufficient stack space\n");
            return false;
        }

        uint8_t testVal = 0xAA;
        SIZE_T wrote = 0;
        st = ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc, (PVOID)stackAddr, &testVal, 1, &wrote);
        bool stackWriteOK = NT_SUCCESS(st) && wrote == 1;
        printf("Stack write test: %s\n", stackWriteOK ? "OK" : "FAIL");
        if (!stackWriteOK) {
            printf("Stack write test failed\n");
            return false;
        }

        uint8_t zero = 0;
        ab_call_fn_cpp<NTSTATUS>("NtWriteVirtualMemory", hProc, (PVOID)stackAddr, &zero, 1, nullptr);
    }
    else {
        printf("Stack validation skipped (pre-injection check)\n");
    }

    MEMORY_BASIC_INFORMATION mbiTramp{};
    SIZE_T retSize;
    NTSTATUS st = ab_call_fn_cpp<NTSTATUS>("NtQueryVirtualMemory", hProc, (PVOID)trampAddr, 0, &mbiTramp, sizeof(mbiTramp), &retSize);
    if (!NT_SUCCESS(st)) {
        printf("Trampoline query failed: 0x%X\n", st);
        return false;
    }

    bool trampValid = (mbiTramp.State == MEM_COMMIT) && ((mbiTramp.Protect & PAGE_EXECUTE_READ) || (mbiTramp.Protect & PAGE_EXECUTE_READWRITE)) && !(mbiTramp.Protect & PAGE_GUARD);

    printf("Tramp[%p]: State=0x%lx Protect=0x%lx SizeAvail=0x%llx %s %s\n",
        (void*)trampAddr, mbiTramp.State, mbiTramp.Protect,
        (unsigned long long)mbiTramp.RegionSize, trampValid ? "OK" : "FAIL",
        trampLowMem ? "(LOW)" : "(HIGH)");

    if (!trampValid) {
        printf("Trampoline protections invalid\n");
        return false;
    }

    bool result = trampValid;
    printf("Validation % s\n\n", result ? "PASS" : "FAIL");
    return result;
}

string N2ResolveDllPath(string_view dllName) {
    char buf[MAX_PATH]{};
    if (!GetModuleFileNameA(nullptr, buf, MAX_PATH)) return {};
    PathRemoveFileSpecA(buf);
    return std::string(buf) + "\\" + std::string(dllName);
}

string N2FindSystemDllPath32(string_view dllName) {
    char sysdir[MAX_PATH]{};
    GetSystemDirectoryA(sysdir, MAX_PATH);
    return std::string(sysdir) + "\\" + std::string(dllName);
}

optional<uintptr_t> N2GetRemoteModuleBase(DWORD pid, string_view moduleName) {
    std::wstring wmod(moduleName.begin(), moduleName.end());

    UniqueHandle hs(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));

    if (!hs.valid()) return {};

    MODULEENTRY32W me{ sizeof(me) };

    if (Module32FirstW(hs.get(), &me)) {
        do {
            if (_wcsicmp(me.szModule, wmod.c_str()) == 0)
                return reinterpret_cast<uintptr_t>(me.modBaseAddr);
        } while (Module32NextW(hs.get(), &me));
    }

    return {};
}

optional<uintptr_t> N2GetExportRVA(string_view dllPath, string_view exportName) {
    UniqueModule mod(LoadLibraryExA(dllPath.data(), nullptr, DONT_RESOLVE_DLL_REFERENCES));
    if (!mod.valid()) return {};

    byte* base = reinterpret_cast<byte*>(mod.get());
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    auto& d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!d.VirtualAddress) return {};

    auto ed = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + d.VirtualAddress);
    auto names = reinterpret_cast<DWORD*>(base + ed->AddressOfNames);
    auto ords = reinterpret_cast<WORD*>(base + ed->AddressOfNameOrdinals);
    auto addrs = reinterpret_cast<DWORD*>(base + ed->AddressOfFunctions);

    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        const char* n = reinterpret_cast<const char*>(base + names[i]);
        if (_stricmp(n, exportName.data()) == 0)
            return static_cast<uintptr_t>(addrs[ords[i]]);
    }
    return {};
}

optional<PVOID> N2ResolveRemoteProc(DWORD pid, string_view dllName, string_view apiName) {
    auto baseOpt = N2GetRemoteModuleBase(pid, dllName);
    if (!baseOpt) return {};

    static constexpr auto sysdlls = std::array<const char*, 5>{ "kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll", "gdi32.dll" };
    string local = [&] {
        auto it = std::find_if(sysdlls.begin(), sysdlls.end(),
            [&](auto& s) { return _stricmp(dllName.data(), s) == 0; });
        return it != sysdlls.end() ? N2FindSystemDllPath32(dllName) : N2ResolveDllPath(dllName);
     }();

    auto rvaOpt = N2GetExportRVA(local, apiName);
    if (!rvaOpt) return {};

    return reinterpret_cast<PVOID>(*baseOpt + *rvaOpt);
}