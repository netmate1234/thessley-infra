#include "kerb_ticket_serialization.h"

#include <ntsecapi.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {

// Keep ticket material bounded even though the public structure uses ULONG
// lengths. Large PACs are valid, so the limit is deliberately generous.
constexpr size_t kMaxTicketBytes = 1024 * 1024;

HRESULT ValidateTicket(const BYTE* bytes, size_t length) {
    if (bytes == nullptr || length == 0) return E_INVALIDARG;
    if (length > kMaxTicketBytes || length > std::numeric_limits<ULONG>::max())
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
    return S_OK;
}

} // namespace

HRESULT BuildKerbTicketSerialization(
    const BYTE* serviceTicket,
    size_t serviceTicketLength,
    const BYTE* forwardedTgtKrbCred,
    size_t forwardedTgtKrbCredLength,
    ULONG kerberosAuthenticationPackage,
    const CLSID& credentialProviderClsid,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) {
    if (serialization == nullptr) return E_POINTER;
    ZeroMemory(serialization, sizeof(*serialization));

    HRESULT hr = ValidateTicket(serviceTicket, serviceTicketLength);
    if (FAILED(hr)) return hr;
    hr = ValidateTicket(forwardedTgtKrbCred, forwardedTgtKrbCredLength);
    if (FAILED(hr)) return hr;
    if (kerberosAuthenticationPackage == 0) return E_INVALIDARG;

    constexpr size_t headerBytes = sizeof(KERB_TICKET_LOGON);
    if (serviceTicketLength > std::numeric_limits<size_t>::max() - headerBytes ||
        headerBytes + serviceTicketLength >
            std::numeric_limits<size_t>::max() - forwardedTgtKrbCredLength)
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);

    const size_t tgtOffset = headerBytes + serviceTicketLength;
    const size_t totalBytes = tgtOffset + forwardedTgtKrbCredLength;
    if (totalBytes > std::numeric_limits<ULONG>::max())
        return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);

    BYTE* buffer = static_cast<BYTE*>(CoTaskMemAlloc(totalBytes));
    if (buffer == nullptr) return E_OUTOFMEMORY;
    ZeroMemory(buffer, totalBytes);

    auto* logon = reinterpret_cast<PKERB_TICKET_LOGON>(buffer);
    logon->MessageType = KerbTicketLogon;
    logon->Flags = 0;
    logon->ServiceTicketLength = static_cast<ULONG>(serviceTicketLength);
    logon->TicketGrantingTicketLength =
        static_cast<ULONG>(forwardedTgtKrbCredLength);
    logon->ServiceTicket = reinterpret_cast<PUCHAR>(
        static_cast<ULONG_PTR>(headerBytes));
    logon->TicketGrantingTicket = reinterpret_cast<PUCHAR>(
        static_cast<ULONG_PTR>(tgtOffset));

    memcpy(buffer + headerBytes, serviceTicket, serviceTicketLength);
    memcpy(buffer + tgtOffset, forwardedTgtKrbCred, forwardedTgtKrbCredLength);

    serialization->ulAuthenticationPackage = kerberosAuthenticationPackage;
    serialization->clsidCredentialProvider = credentialProviderClsid;
    serialization->cbSerialization = static_cast<ULONG>(totalBytes);
    serialization->rgbSerialization = buffer;
    return S_OK;
}

void FreeKerbTicketSerialization(
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization) {
    if (serialization == nullptr) return;
    if (serialization->rgbSerialization != nullptr) {
        SecureZeroMemory(serialization->rgbSerialization,
                         serialization->cbSerialization);
        CoTaskMemFree(serialization->rgbSerialization);
    }
    ZeroMemory(serialization, sizeof(*serialization));
}
