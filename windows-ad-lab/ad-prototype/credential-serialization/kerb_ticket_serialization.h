#pragma once

#include <windows.h>
#include <credentialprovider.h>

#include <cstddef>

// Packages KDC-issued Kerberos tickets for the built-in Kerberos package.
// serviceTicket must be the PAC-bearing host/<computer> service ticket;
// forwardedTgtKrbCred must be a KRB_CRED containing the forwardable TGT.
// Both inputs are sensitive credentials and must come directly from the
// authenticated PKINIT flow, remain in memory, and be wiped after handoff.
HRESULT BuildKerbTicketSerialization(
    const BYTE* serviceTicket,
    size_t serviceTicketLength,
    const BYTE* forwardedTgtKrbCred,
    size_t forwardedTgtKrbCredLength,
    bool unlockScenario,
    const LUID* logonId,
    ULONG kerberosAuthenticationPackage,
    const CLSID& credentialProviderClsid,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
    bool nativePointerFields = false);

// Securely discards a ticket serialization before it is handed to LogonUI.
void FreeKerbTicketSerialization(
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization);
