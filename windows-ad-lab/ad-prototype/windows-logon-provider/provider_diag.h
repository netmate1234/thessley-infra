#pragma once

#include <windows.h>
#include <ntsecapi.h>

// Logs lifecycle events, numeric results, and fixed nonsecret metadata only.
// Never pass identity, password, PIN, QR, or approval data to this function.
void ProviderDiag(const wchar_t *eventName, HRESULT result = S_OK, DWORD count = 0,
                  const wchar_t *detail = nullptr);

// Explicitly records the separate NTSTATUS fields returned by LSA. The generic
// ProviderDiag count field is decimal and made the substatus easy to misread.
// This writes only protocol metadata, never credential or ticket contents.
void ProviderDiagTicketStatus(const wchar_t *eventName, NTSTATUS status,
                              NTSTATUS substatus, DWORD usageScenario,
                              ULONG authenticationPackage,
                              DWORD serializedBytes);
