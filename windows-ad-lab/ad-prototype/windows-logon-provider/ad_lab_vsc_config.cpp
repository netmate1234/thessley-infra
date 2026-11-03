#include "ad_lab_vsc_config.h"

#include <wincrypt.h>
#include <cwchar>
#include <string>
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

    DWORD pivMode = 0;
    DWORD pivModeBytes = sizeof(pivMode);
    const LSTATUS pivModeStatus = RegGetValueW(
        key, nullptr, L"PivPhoneSigning", RRF_RT_REG_DWORD, nullptr, &pivMode, &pivModeBytes);
    config->pivPhoneSigning = pivModeStatus == ERROR_SUCCESS && pivModeBytes == sizeof(pivMode)
        && pivMode == 1
        && ReadString(key, L"PivContainerName", &config->pivContainerName, true)
        && ReadString(key, L"PivProviderName", &config->pivProviderName, true)
        && ReadString(key, L"PivReaderName", &config->pivReaderName, true)
        && ReadString(key, L"PivCardName", &config->pivCardName, false);
    DWORD pivKeySpec = 0;
    DWORD pivKeySpecBytes = sizeof(pivKeySpec);
    const LSTATUS pivKeySpecStatus = RegGetValueW(
        key, nullptr, L"PivKeySpec", RRF_RT_REG_DWORD, nullptr, &pivKeySpec, &pivKeySpecBytes);
    config->pivPhoneSigning = config->pivPhoneSigning && pivKeySpecStatus == ERROR_SUCCESS
        && pivKeySpecBytes == sizeof(pivKeySpec)
        && (pivKeySpec == AT_KEYEXCHANGE || pivKeySpec == AT_SIGNATURE);
    DWORD passwordPlusPhone = 0;
    DWORD passwordPlusPhoneBytes = sizeof(passwordPlusPhone);
    const LSTATUS passwordPlusPhoneStatus = RegGetValueW(
        key, nullptr, L"PasswordPlusPhoneTest", RRF_RT_REG_DWORD, nullptr,
        &passwordPlusPhone, &passwordPlusPhoneBytes);
    config->passwordPlusPhoneTest = passwordPlusPhoneStatus == ERROR_SUCCESS
        && passwordPlusPhoneBytes == sizeof(passwordPlusPhone)
        && passwordPlusPhone == 1;
    if (config->pivPhoneSigning) {
        config->pivKeySpec = pivKeySpec;
        // The opt-in phone PIV mode supersedes the isolated ticket experiment.
        config->ticketLogonTest = false;
    }
    RegCloseKey(key);

    if (!validVsc && !config->ticketLogonTest && !config->pivPhoneSigning &&
        !config->passwordPlusPhoneTest)
    {
        *config = AdLabVscConfig{};
        return false;
    }
    if (config->passwordPlusPhoneTest && !validVsc && !config->ticketLogonTest &&
        !config->pivPhoneSigning) {
        // Password-plus-phone is permitted only for an account already
        // explicitly configured for Thessley AD testing.
        *config = AdLabVscConfig{};
        return false;
    }
    if (validVsc) config->keySpec = keySpec;
    return true;
}

bool SetAdLabPivRequestId(const wchar_t *sid, const wchar_t *requestId)
{
    if (!IsCanonicalSidText(sid)) return false;
    if (requestId)
    {
        const size_t length = wcslen(requestId);
        if (length < 8 || length > 128) return false;
        for (const wchar_t *p = requestId; *p; ++p)
            if (!((*p >= L'A' && *p <= L'Z') || (*p >= L'a' && *p <= L'z') ||
                  (*p >= L'0' && *p <= L'9') || *p == L'_' || *p == L'-')) return false;
    }
    std::wstring path(kConfigPath);
    path.append(sid);
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                      KEY_SET_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) return false;
    LSTATUS status;
    if (!requestId || !*requestId) {
        status = RegDeleteValueW(key, L"PivPhoneRequestId");
        if (status == ERROR_FILE_NOT_FOUND) status = ERROR_SUCCESS;
    } else {
        const DWORD bytes = static_cast<DWORD>((wcslen(requestId) + 1) * sizeof(wchar_t));
        status = RegSetValueExW(key, L"PivPhoneRequestId", 0, REG_SZ,
                                reinterpret_cast<const BYTE *>(requestId), bytes);
    }
    RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

bool GetAdLabPivRequestId(const wchar_t *sid, std::wstring *requestId)
{
    if (!requestId || !IsCanonicalSidText(sid)) return false;
    requestId->clear();
    std::wstring path(kConfigPath);
    path.append(sid);
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return false;

    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS status = RegQueryValueExW(key, L"PivPhoneRequestId", nullptr,
                                      &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || type != REG_SZ || bytes < 9 * sizeof(wchar_t) ||
        bytes > 129 * sizeof(wchar_t) || bytes % sizeof(wchar_t) != 0)
    {
        RegCloseKey(key);
        return false;
    }
    std::vector<wchar_t> value(bytes / sizeof(wchar_t), L'\0');
    status = RegQueryValueExW(key, L"PivPhoneRequestId", nullptr, &type,
                              reinterpret_cast<BYTE *>(value.data()), &bytes);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_SZ || value.back() != L'\0')
        return false;
    const std::wstring candidate(value.data());
    if (candidate.size() < 8 || candidate.size() > 128) return false;
    for (wchar_t c : candidate)
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
              (c >= L'0' && c <= L'9') || c == L'_' || c == L'-'))
            return false;
    *requestId = candidate;
    return true;
}
