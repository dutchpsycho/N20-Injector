#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        MessageBoxW(NULL, L"Loaded N20 DLL", L"Injected via N20", MB_OK);
    }
    return TRUE;
}