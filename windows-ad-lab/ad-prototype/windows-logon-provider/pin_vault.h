#pragma once

#include <windows.h>
#include <string>
#include <vector>

bool ThessleyPinVaultExists(PCWSTR sid);
HRESULT ThessleyPinVaultLoad(PCWSTR sid, std::vector<WCHAR>& pin);
HRESULT ThessleyPinVaultSave(PCWSTR sid, PCWSTR pin);
void ThessleySecureClear(std::vector<WCHAR>& value);
