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
    std::wstring pivCardName;
    std::wstring pivReaderName;
    std::wstring pivContainerName;
    std::wstring pivProviderName;
    DWORD keySpec = 0;
    DWORD pivKeySpec = 0;
    bool ticketLogonTest = false;
    bool pivPhoneSigning = false;
    bool passwordPlusPhoneTest = false;
};

bool LoadAdLabVscConfig(const wchar_t *sid, AdLabVscConfig *config);
bool SetAdLabPivRequestId(const wchar_t *sid, const wchar_t *requestId);
bool GetAdLabPivRequestId(const wchar_t *sid, std::wstring *requestId);
