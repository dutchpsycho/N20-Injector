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

bool N2Inject(DWORD pid, const char* targetDll, const char* targetApi, const char* dllPath);