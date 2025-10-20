#pragma once
#include <windows.h>
#include <optional>

std::optional<DWORD> N2TargetThread(HANDLE hProcess);
void N2TeleportThreadExecutionLikeJagger(HANDLE processHandle, HANDLE threadHandle, uintptr_t desiredAddr);