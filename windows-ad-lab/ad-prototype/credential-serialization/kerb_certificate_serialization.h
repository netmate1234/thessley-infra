#pragma once

#include <windows.h>
#include <credentialprovider.h>

// Builds the Kerberos smart-card credential serialization for the separate AD
// prototype. protectedPin must already be protected with CredProtect; this
// function rejects an unprotected PIN. On success, the caller returns the
// serialization to LogonUI and must not free or inspect it after handoff.
HRESULT BuildKerbCertificateSerialization(
    PCWSTR domain,
    PCWSTR user,
    PCWSTR protectedPin,
    PCWSTR cardName,
    PCWSTR readerName,
    PCWSTR containerName,
    PCWSTR providerName,
    DWORD keySpec,
    bool unlockScenario,
    const LUID* logonId,
    ULONG authenticationPackage,
    const CLSID& credentialProviderClsid,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization,
    bool allowEmptyPin = false);

// Securely discards a serialization if it has not been handed to LogonUI.
void FreeKerbCertificateSerialization(
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization);
