#include "kerb_certificate_serialization.h"

#include <ntsecapi.h>
#include <wincrypt.h>
#include <wincred.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

// Microsoft documents this structure as private to the Kerberos smart-card
// serialization contract. The 2-byte packing and WCHAR-relative offsets are
// required by that contract.
#pragma pack(push, 2)
typedef struct _THESSLEY_KERB_SMARTCARD_CSP_INFO {
    DWORD dwCspInfoLen;
    DWORD MessageType;
    union {
        PVOID ContextInformation;
        ULONG64 SpaceHolderForWow64;
    };
    DWORD flags;
    DWORD KeySpec;
    ULONG nCardNameOffset;
    ULONG nReaderNameOffset;
    ULONG nContainerNameOffset;
    ULONG nCSPNameOffset;
    WCHAR bBuffer;
} THESSLEY_KERB_SMARTCARD_CSP_INFO;
#pragma pack(pop)

namespace {

HRESULT ValidateInput(PCWSTR value, bool required, size_t* chars) {
    if (chars == nullptr) return E_POINTER;
    if (value == nullptr) {
        if (required) return E_INVALIDARG;
        *chars = 1; // Empty, null-terminated optional string.
        return S_OK;
    }
    const size_t length = wcslen(value);
    if (required && length == 0) return E_INVALIDARG;
    if (length > (std::numeric_limits<USHORT>::max() / sizeof(WCHAR)) - 1)
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
    *chars = length + 1;
    return S_OK;
}

void SetRelativeUnicodeString(PUNICODE_STRING target, BYTE* base,
                              size_t offset, PCWSTR value) {
    const size_t length = wcslen(value);
    target->Length = static_cast<USHORT>(length * sizeof(WCHAR));
    target->MaximumLength = static_cast<USHORT>((length + 1) * sizeof(WCHAR));
    target->Buffer = reinterpret_cast<PWSTR>(static_cast<ULONG_PTR>(offset));
    memcpy(base + offset, value, (length + 1) * sizeof(WCHAR));
}

HRESULT BuildCspInfo(PCWSTR cardName, PCWSTR readerName,
                     PCWSTR containerName, PCWSTR providerName,
                     DWORD keySpec, std::vector<BYTE>* output) {
    if (output == nullptr) return E_POINTER;

    size_t cardChars = 0, readerChars = 0, containerChars = 0, providerChars = 0;
    HRESULT hr = ValidateInput(cardName, false, &cardChars);
    if (FAILED(hr)) return hr;
    hr = ValidateInput(readerName, false, &readerChars);
    if (FAILED(hr)) return hr;
    hr = ValidateInput(containerName, true, &containerChars);
    if (FAILED(hr)) return hr;
    hr = ValidateInput(providerName, false, &providerChars);
    if (FAILED(hr)) return hr;
    // KERB_SMARTCARD_CSP_INFO.KeySpec is the legacy key-usage selector even
    // when ProviderName identifies a CNG KSP. Kerberos smart-card logon only
    // accepts AT_KEYEXCHANGE or AT_SIGNATURE here; the certificate's CNG
    // dwKeySpec value (0) must not be copied into this separate field.
    if (keySpec != AT_KEYEXCHANGE && keySpec != AT_SIGNATURE)
        return E_INVALIDARG;

    // The bBuffer starts with a DWORD reserved prefix (two WCHARs), followed
    // by four null-terminated names. Offsets are WCHAR counts from bBuffer.
    constexpr size_t prefixChars = sizeof(DWORD) / sizeof(WCHAR);
    const size_t totalChars = prefixChars + cardChars + readerChars +
                              containerChars + providerChars;
    const size_t headerBytes = offsetof(THESSLEY_KERB_SMARTCARD_CSP_INFO, bBuffer);
    if (totalChars > (std::numeric_limits<DWORD>::max() - headerBytes) / sizeof(WCHAR))
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
    const size_t totalBytes = headerBytes + totalChars * sizeof(WCHAR);

    try {
        output->assign(totalBytes, 0);
    } catch (...) {
        return E_OUTOFMEMORY;
    }

    auto* info = reinterpret_cast<THESSLEY_KERB_SMARTCARD_CSP_INFO*>(output->data());
    info->dwCspInfoLen = static_cast<DWORD>(totalBytes);
    info->MessageType = 1;
    info->KeySpec = keySpec;
    info->nCardNameOffset = static_cast<ULONG>(prefixChars);
    info->nReaderNameOffset = static_cast<ULONG>(info->nCardNameOffset + cardChars);
    info->nContainerNameOffset = static_cast<ULONG>(info->nReaderNameOffset + readerChars);
    info->nCSPNameOffset = static_cast<ULONG>(info->nContainerNameOffset + containerChars);

    WCHAR* names = &info->bBuffer;
    wcscpy_s(names + info->nCardNameOffset, cardChars, cardName ? cardName : L"");
    wcscpy_s(names + info->nReaderNameOffset, readerChars, readerName ? readerName : L"");
    wcscpy_s(names + info->nContainerNameOffset, containerChars, containerName);
    wcscpy_s(names + info->nCSPNameOffset, providerChars, providerName ? providerName : L"");
    return S_OK;
}

} // namespace

HRESULT BuildKerbCertificateSerialization(
    PCWSTR domain, PCWSTR user, PCWSTR protectedPin,
    PCWSTR cardName, PCWSTR readerName, PCWSTR containerName,
    PCWSTR providerName, DWORD keySpec, bool unlockScenario,
    const LUID* logonId, ULONG authenticationPackage,
    const CLSID& credentialProviderClsid,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
    bool allowEmptyPin) {
    if (serialization == nullptr) return E_POINTER;
    ZeroMemory(serialization, sizeof(*serialization));

    size_t domainChars = 0, userChars = 0, pinChars = 0;
    HRESULT hr = ValidateInput(domain, true, &domainChars);
    if (FAILED(hr)) return hr;
    hr = ValidateInput(user, true, &userChars);
    if (FAILED(hr)) return hr;
    const bool emptyPin = protectedPin != nullptr && protectedPin[0] == L'\0';
    if (emptyPin && !allowEmptyPin) return E_INVALIDARG;
    if (protectedPin == nullptr) return E_INVALIDARG;
    hr = ValidateInput(protectedPin, !allowEmptyPin, &pinChars);
    if (FAILED(hr)) return hr;
    if (unlockScenario && logonId == nullptr) return E_INVALIDARG;

    if (!emptyPin) {
        CRED_PROTECTION_TYPE protection = CredUnprotected;
        if (!CredIsProtectedW(const_cast<PWSTR>(protectedPin), &protection) ||
            protection == CredUnprotected)
            return HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD);
    } else if (!allowEmptyPin) {
        return HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD);
    } else {
        const bool noReader = (!cardName || !*cardName) &&
                              (!readerName || !*readerName);
        const bool probeProvider =
            !providerName || !*providerName ||
            _wcsicmp(providerName, L"Microsoft Software Key Storage Provider") == 0 ||
            _wcsicmp(providerName, L"Microsoft Platform Crypto Provider") == 0 ||
            _wcsicmp(providerName, L"Microsoft Enhanced RSA and AES Cryptographic Provider") == 0;
        // Empty PIN is limited to a disposable no-reader probe with an
        // explicit built-in provider. KSP behavior through this legacy
        // structure is experimental; this does not establish production
        // smart-card compatibility. Never bypass a smart-card PIN.
        if (!noReader || !probeProvider) return E_ACCESSDENIED;
    }

    std::vector<BYTE> cspInfo;
    hr = BuildCspInfo(cardName, readerName, containerName, providerName,
                      keySpec, &cspInfo);
    if (FAILED(hr)) return hr;

    const size_t headerBytes = unlockScenario
        ? sizeof(KERB_CERTIFICATE_UNLOCK_LOGON)
        : sizeof(KERB_CERTIFICATE_LOGON);
    const size_t domainBytes = domainChars * sizeof(WCHAR);
    const size_t userBytes = userChars * sizeof(WCHAR);
    const size_t pinBytes = pinChars * sizeof(WCHAR);
    if (headerBytes > std::numeric_limits<DWORD>::max() - domainBytes ||
        headerBytes + domainBytes > std::numeric_limits<DWORD>::max() - userBytes ||
        headerBytes + domainBytes + userBytes > std::numeric_limits<DWORD>::max() - pinBytes ||
        headerBytes + domainBytes + userBytes + pinBytes >
            std::numeric_limits<DWORD>::max() - cspInfo.size())
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);

    const size_t domainOffset = headerBytes;
    const size_t userOffset = domainOffset + domainBytes;
    const size_t pinOffset = userOffset + userBytes;
    const size_t cspOffset = pinOffset + pinBytes;
    const size_t totalBytes = cspOffset + cspInfo.size();
    BYTE* buffer = static_cast<BYTE*>(CoTaskMemAlloc(totalBytes));
    if (buffer == nullptr) return E_OUTOFMEMORY;
    ZeroMemory(buffer, totalBytes);

    auto* logon = reinterpret_cast<PKERB_CERTIFICATE_LOGON>(buffer);
    logon->MessageType = unlockScenario
        ? KerbCertificateUnlockLogon
        : KerbCertificateLogon;
    SetRelativeUnicodeString(&logon->DomainName, buffer, domainOffset, domain);
    SetRelativeUnicodeString(&logon->UserName, buffer, userOffset, user);
    SetRelativeUnicodeString(&logon->Pin, buffer, pinOffset, protectedPin);
    logon->Flags = KERB_CERTIFICATE_LOGON_FLAG_CHECK_DUPLICATES;
    logon->CspDataLength = static_cast<ULONG>(cspInfo.size());
    logon->CspData = reinterpret_cast<PUCHAR>(static_cast<ULONG_PTR>(cspOffset));
    memcpy(buffer + cspOffset, cspInfo.data(), cspInfo.size());

    if (unlockScenario) {
        auto* unlock = reinterpret_cast<PKERB_CERTIFICATE_UNLOCK_LOGON>(buffer);
        unlock->LogonId = *logonId;
    }

    serialization->ulAuthenticationPackage = authenticationPackage;
    serialization->clsidCredentialProvider = credentialProviderClsid;
    serialization->cbSerialization = static_cast<ULONG>(totalBytes);
    serialization->rgbSerialization = buffer;
    return S_OK;
}

void FreeKerbCertificateSerialization(
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) {
    if (serialization == nullptr) return;
    if (serialization->rgbSerialization != nullptr) {
        SecureZeroMemory(serialization->rgbSerialization,
                         serialization->cbSerialization);
        CoTaskMemFree(serialization->rgbSerialization);
    }
    ZeroMemory(serialization, sizeof(*serialization));
}
