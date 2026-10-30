#pragma once

#include <windows.h>
#include <string>

// Per-account lab configuration is stored under the 64-bit HKLM registry
// view. Missing, malformed, or incomplete values fail closed.
struct AdLabVscConfig
{
    std::wstring cardName;
    std::wstring readerName;
    std::wstring containerName;
    std::wstring providerName;
    DWORD keySpec = 0;
    bool ticketLogonTest = false;
};

bool LoadAdLabVscConfig(const wchar_t *sid, AdLabVscConfig *config);
