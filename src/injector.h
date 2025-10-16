#pragma once

#include <windows.h>

// Injects the DLL at dllPath into process pid by hooking the provided dll/api.
// Returns true on success, false on failure.
bool InjectDll(DWORD pid, const char* targetDll, const char* targetApi, const char* dllPath);