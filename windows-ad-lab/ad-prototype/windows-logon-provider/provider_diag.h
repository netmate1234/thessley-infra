#pragma once

#include <windows.h>

// Logs lifecycle events, numeric results, and fixed nonsecret metadata only.
// Never pass identity, password, PIN, QR, or approval data to this function.
void ProviderDiag(const wchar_t *eventName, HRESULT result = S_OK, DWORD count = 0,
                  const wchar_t *detail = nullptr);
