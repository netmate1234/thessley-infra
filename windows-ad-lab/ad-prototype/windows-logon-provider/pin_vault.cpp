#include "pin_vault.h"

#include <dpapi.h>
#include <sddl.h>
#include <cstring>
#include <cwchar>
#include <vector>

namespace {
constexpr PCWSTR kDirectory = L"C:\\ProgramData\\ThessleyPamWin\\ad-credential-provider\\pins";
constexpr size_t kMaxPinChars = 256;
constexpr DWORD kMaxBlobBytes = 4096;

bool PathFor(PCWSTR sidText, std::wstring& path) {
    if (!sidText || !*sidText) return false;
    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(sidText, &sid)) return false;
    if (!IsValidSid(sid)) { LocalFree(sid); return false; }
    LPWSTR canonical = nullptr;
    const BOOL ok = ConvertSidToStringSidW(sid, &canonical);
    LocalFree(sid);
    if (!ok) return false;
    path.assign(kDirectory).append(L"\\").append(canonical).append(L".bin");
    LocalFree(canonical);
    return true;
}

bool EntropyFor(PCWSTR sidText, std::vector<BYTE>& entropy) {
    std::wstring context = L"Thessley AD VSC PIN vault v1|";
    context.append(sidText);
    entropy.resize((context.size() + 1) * sizeof(WCHAR));
    memcpy(entropy.data(), context.c_str(), entropy.size());
    SecureZeroMemory(context.data(), context.size() * sizeof(WCHAR));
    return true;
}

HRESULT EnsureDirectory() {
    if (CreateDirectoryW(kDirectory, nullptr)) return S_OK;
    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS) return HRESULT_FROM_WIN32(error);
    const DWORD attrs = GetFileAttributesW(kDirectory);
    if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY) ||
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    return S_OK;
}
}

bool ThessleyPinVaultExists(PCWSTR sid) {
    std::wstring path;
    if (!PathFor(sid, path)) return false;
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

HRESULT ThessleyPinVaultLoad(PCWSTR sid, std::vector<WCHAR>& pin) {
    ThessleySecureClear(pin);
    std::wstring path;
    std::vector<BYTE> entropy;
    if (!PathFor(sid, path) || !EntropyFor(sid, entropy)) return E_INVALIDARG;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
    BY_HANDLE_FILE_INFORMATION info{};
    LARGE_INTEGER size{};
    bool valid = GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
        GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= kMaxBlobBytes;
    std::vector<BYTE> blob;
    if (valid) {
        blob.resize(static_cast<size_t>(size.QuadPart));
        DWORD got = 0;
        valid = ReadFile(file, blob.data(), static_cast<DWORD>(blob.size()), &got, nullptr) && got == blob.size();
    }
    CloseHandle(file);
    if (!valid) { if (!blob.empty()) SecureZeroMemory(blob.data(), blob.size()); return HRESULT_FROM_WIN32(ERROR_INVALID_DATA); }
    DATA_BLOB input{static_cast<DWORD>(blob.size()), blob.data()};
    DATA_BLOB optionalEntropy{static_cast<DWORD>(entropy.size()), entropy.data()};
    DATA_BLOB clear{};
    const BOOL ok = CryptUnprotectData(&input, nullptr, &optionalEntropy, nullptr, nullptr,
                                       CRYPTPROTECT_UI_FORBIDDEN, &clear);
    SecureZeroMemory(blob.data(), blob.size());
    SecureZeroMemory(entropy.data(), entropy.size());
    if (!ok) return HRESULT_FROM_WIN32(GetLastError());
    HRESULT result = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (clear.cbData >= sizeof(WCHAR) && clear.cbData <= (kMaxPinChars + 1) * sizeof(WCHAR) &&
        clear.cbData % sizeof(WCHAR) == 0) {
        const auto* chars = reinterpret_cast<const WCHAR*>(clear.pbData);
        const size_t count = clear.cbData / sizeof(WCHAR);
        if (chars[count - 1] == L'\0') {
            size_t length = 0;
            while (length + 1 < count && chars[length] != L'\0') ++length;
            if (length > 0 && length + 1 == count) { pin.assign(chars, chars + count); result = S_OK; }
        }
    }
    SecureZeroMemory(clear.pbData, clear.cbData);
    LocalFree(clear.pbData);
    return result;
}

HRESULT ThessleyPinVaultSave(PCWSTR sid, PCWSTR pin) {
    if (!sid || !pin || !*pin) return E_INVALIDARG;
    const size_t length = wcsnlen(pin, kMaxPinChars + 1);
    if (length == 0 || length > kMaxPinChars) return HRESULT_FROM_WIN32(ERROR_INVALID_PASSWORD);
    std::wstring path;
    std::vector<BYTE> entropy;
    if (!PathFor(sid, path) || !EntropyFor(sid, entropy)) return E_INVALIDARG;
    HRESULT hr = EnsureDirectory();
    if (FAILED(hr)) return hr;
    DATA_BLOB input{static_cast<DWORD>((length + 1) * sizeof(WCHAR)), reinterpret_cast<BYTE*>(const_cast<PWSTR>(pin))};
    DATA_BLOB optionalEntropy{static_cast<DWORD>(entropy.size()), entropy.data()};
    DATA_BLOB encrypted{};
    const BOOL protectedOk = CryptProtectData(&input, L"Thessley AD card PIN", &optionalEntropy,
        nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &encrypted);
    SecureZeroMemory(entropy.data(), entropy.size());
    if (!protectedOk) return HRESULT_FROM_WIN32(GetLastError());
    if (encrypted.cbData == 0 || encrypted.cbData > kMaxBlobBytes) {
        SecureZeroMemory(encrypted.pbData, encrypted.cbData); LocalFree(encrypted.pbData);
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    std::wstring temp = path + L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64());
    HANDLE file = CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        hr = HRESULT_FROM_WIN32(GetLastError()); SecureZeroMemory(encrypted.pbData, encrypted.cbData); LocalFree(encrypted.pbData); return hr;
    }
    DWORD written = 0;
    const bool wrote = WriteFile(file, encrypted.pbData, encrypted.cbData, &written, nullptr) && written == encrypted.cbData && FlushFileBuffers(file);
    CloseHandle(file);
    SecureZeroMemory(encrypted.pbData, encrypted.cbData); LocalFree(encrypted.pbData);
    if (!wrote) { const DWORD error = GetLastError(); DeleteFileW(temp.c_str()); return HRESULT_FROM_WIN32(error ? error : ERROR_WRITE_FAULT); }
    if (!MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        hr = HRESULT_FROM_WIN32(GetLastError()); DeleteFileW(temp.c_str()); return hr;
    }
    return S_OK;
}
