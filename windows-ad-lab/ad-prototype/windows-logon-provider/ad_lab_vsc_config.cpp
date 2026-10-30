#include "ad_lab_vsc_config.h"

#include <wincrypt.h>
#include <vector>

namespace
{
constexpr wchar_t kConfigPath[] = L"SOFTWARE\\Thessley\\ADCredentialProvider\\Users\\";

bool IsCanonicalSidText(const wchar_t *sid)
{
    if (!sid || sid[0] != L'S' || sid[1] != L'-') return false;
    size_t length = 0;
    for (const wchar_t *p = sid + 2; *p; ++p)
    {
        if (*p != L'-' && (*p < L'0' || *p > L'9')) return false;
        if (++length > 184) return false;
    }
    return length >= 5;
}

bool ReadString(HKEY key, const wchar_t *name, std::wstring *value, bool required)
{
    DWORD bytes = 0;
    LSTATUS status = RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, nullptr, &bytes);
    if (status != ERROR_SUCCESS)
    {
        if (!required && status == ERROR_FILE_NOT_FOUND)
        {
            value->clear();
            return true;
        }
        return false;
    }
    if (bytes < sizeof(wchar_t) || bytes > 4096 || bytes % sizeof(wchar_t) != 0) return false;

    std::vector<wchar_t> buffer(bytes / sizeof(wchar_t), L'\0');
    status = RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr,
                          buffer.data(), &bytes);
    if (status != ERROR_SUCCESS || buffer.back() != L'\0') return false;
    value->assign(buffer.data());
    if (value->size() > 255) return false;
    return !required || !value->empty();
}
}

bool LoadAdLabVscConfig(const wchar_t *sid, AdLabVscConfig *config)
{
    if (!config || !IsCanonicalSidText(sid)) return false;
    *config = AdLabVscConfig{};

    std::wstring path(kConfigPath);
    path.append(sid);

    HKEY key = nullptr;
    const LSTATUS openStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                                             KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key);
    if (openStatus != ERROR_SUCCESS) return false;

    DWORD keySpec = 0;
    DWORD keySpecBytes = sizeof(keySpec);
    const LSTATUS keySpecStatus = RegGetValueW(key, nullptr, L"KeySpec", RRF_RT_REG_DWORD,
                                               nullptr, &keySpec, &keySpecBytes);
    const bool validVsc = keySpecStatus == ERROR_SUCCESS && keySpecBytes == sizeof(keySpec)
        && (keySpec == AT_KEYEXCHANGE || keySpec == AT_SIGNATURE)
        && ReadString(key, L"ContainerName", &config->containerName, true)
        && ReadString(key, L"ProviderName", &config->providerName, true)
        && ReadString(key, L"ReaderName", &config->readerName, false)
        && ReadString(key, L"CardName", &config->cardName, false);
    DWORD ticketMode = 0;
    DWORD ticketModeBytes = sizeof(ticketMode);
    const LSTATUS ticketModeStatus = RegGetValueW(
        key, nullptr, L"TicketLogonTest", RRF_RT_REG_DWORD, nullptr,
        &ticketMode, &ticketModeBytes);
    config->ticketLogonTest = ticketModeStatus == ERROR_SUCCESS &&
        ticketModeBytes == sizeof(ticketMode) && ticketMode == 1;
    RegCloseKey(key);

    if (!validVsc && !config->ticketLogonTest)
    {
        *config = AdLabVscConfig{};
        return false;
    }
    if (validVsc) config->keySpec = keySpec;
    return true;
}
