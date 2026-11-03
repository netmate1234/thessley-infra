//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include <wincrypt.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstring>
#include "CSampleCredential.h"
#include "guid.h"
#include "provider_diag.h"
#include "ad_approval_client.h"
#include "ad_ticket_broker_protocol.h"
#include "kerb_certificate_serialization.h"
#include "kerb_ticket_serialization.h"
#include "password_vault.h"

// Releasing the worker's final COM reference on the worker itself can destroy
// CSampleCredential while its std::thread member is still joinable. The
// std::thread destructor then calls std::terminate, which takes down LogonUI.
// Transfer that reference to a pool thread; the destructor can safely join the
// completed approval worker from there.
static DWORD WINAPI ReleaseCredentialReference(LPVOID context)
{
    static_cast<CSampleCredential *>(context)->Release();
    return 0;
}

static bool IsTicketLogonTestMode(const AdLabVscConfig& config)
{
#ifdef THESSLEY_TICKET_LOGON_TEST
    return config.ticketLogonTest;
#else
    (void)config;
    return false;
#endif
}

static bool IsPivPhoneTestMode(const AdLabVscConfig& config)
{
    return config.pivPhoneSigning && !config.passwordPlusPhoneTest;
}

static bool IsAdPasswordPlusPhoneTestMode(const AdLabVscConfig& config)
{
    return config.passwordPlusPhoneTest;
}

// Identify local accounts from the machine SAM SID, not the provider ID or
// display name. LogonUI can surface domain profiles through the local-user
// provider, and name formats can vary between DOMAIN\\user and MACHINE\\user.
static bool IsLocalSamAccountSid(PCWSTR sidText)
{
    if (!sidText || !*sidText) return false;
    PSID accountSid = nullptr;
    if (!ConvertStringSidToSidW(sidText, &accountSid)) return false;

    LSA_OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    LSA_HANDLE policy = nullptr;
    NTSTATUS status = LsaOpenPolicy(nullptr, &attributes,
                                    POLICY_VIEW_LOCAL_INFORMATION, &policy);
    PPOLICY_ACCOUNT_DOMAIN_INFO info = nullptr;
    if (status >= 0)
        status = LsaQueryInformationPolicy(policy, PolicyAccountDomainInformation,
                                           reinterpret_cast<PVOID *>(&info));

    bool isLocal = false;
    if (status >= 0 && info && info->DomainSid && IsValidSid(accountSid))
    {
        const UCHAR localCount = *GetSidSubAuthorityCount(info->DomainSid);
        const UCHAR accountCount = *GetSidSubAuthorityCount(accountSid);
        const SID_IDENTIFIER_AUTHORITY *localAuthority = GetSidIdentifierAuthority(info->DomainSid);
        const SID_IDENTIFIER_AUTHORITY *accountAuthority = GetSidIdentifierAuthority(accountSid);
        isLocal = localAuthority && accountAuthority && accountCount == localCount + 1 &&
            std::memcmp(localAuthority, accountAuthority, sizeof(*localAuthority)) == 0;
        for (UCHAR index = 0; isLocal && index < localCount; ++index)
            isLocal = *GetSidSubAuthority(info->DomainSid, index) ==
                      *GetSidSubAuthority(accountSid, index);
    }

    if (info) LsaFreeMemory(info);
    if (policy) LsaClose(policy);
    LocalFree(accountSid);
    return isLocal;
}

// CPUS_LOGON is also used by LogonUI while unlocking an existing console
// session on some Windows builds. In that case KerbCertificateLogon creates
// a separate logon context, leaving the shell's original ticket cache empty.
// Identify the existing console user's AuthenticationId so the caller can
// use KERB_CERTIFICATE_UNLOCK_LOGON instead. WTSQueryUserToken requires
// SeTcbPrivilege, which LogonUI does not hold. Read the token statistics of
// the existing shell process instead; the process/token handles are query-only
// and are immediately closed.
static HRESULT GetActiveConsoleLogonIdForSid(PCWSTR expectedSid, bool requireLocked,
                                            DWORD* sessionId, LUID* logonId)
{
    if (!expectedSid || !sessionId || !logonId) return E_POINTER;
    *sessionId = 0xffffffff;
    ZeroMemory(logonId, sizeof(*logonId));

    const DWORD activeSession = WTSGetActiveConsoleSessionId();
    if (activeSession == 0xffffffff)
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    LPWSTR sessionInfoBuffer = nullptr;
    DWORD sessionInfoBytes = 0;
    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, activeSession,
                                     WTSSessionInfoEx, &sessionInfoBuffer,
                                     &sessionInfoBytes))
        return HRESULT_FROM_WIN32(GetLastError());
    const auto* sessionInfo = reinterpret_cast<const WTSINFOEXW*>(sessionInfoBuffer);
    const bool isLocked = sessionInfoBytes >= sizeof(WTSINFOEXW) &&
        sessionInfo->Level == 1 &&
        sessionInfo->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK;
    WTSFreeMemory(sessionInfoBuffer);
    if (requireLocked && !isLocked)
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);

    PSID expected = nullptr;
    if (!ConvertStringSidToSidW(expectedSid, &expected))
        return HRESULT_FROM_WIN32(GetLastError());

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        const HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
        LocalFree(expected);
        return hr;
    }

    HRESULT result = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, L"StartMenuExperienceHost.exe") != 0 &&
                _wcsicmp(entry.szExeFile, L"explorer.exe") != 0)
                continue;

            DWORD processSession = 0xffffffff;
            if (!ProcessIdToSessionId(entry.th32ProcessID, &processSession) ||
                processSession != activeSession)
                continue;

            HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                         entry.th32ProcessID);
            if (!process) { result = HRESULT_FROM_WIN32(GetLastError()); continue; }
            HANDLE token = nullptr;
            if (!OpenProcessToken(process, TOKEN_QUERY, &token))
            {
                result = HRESULT_FROM_WIN32(GetLastError());
                CloseHandle(process);
                continue;
            }

            DWORD bytes = 0;
            GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
            {
                result = HRESULT_FROM_WIN32(GetLastError());
                CloseHandle(token);
                CloseHandle(process);
                continue;
            }
            std::vector<BYTE> tokenUserBuffer(bytes);
            if (!GetTokenInformation(token, TokenUser, tokenUserBuffer.data(), bytes, &bytes))
            {
                result = HRESULT_FROM_WIN32(GetLastError());
                CloseHandle(token);
                CloseHandle(process);
                continue;
            }
            const bool sameUser = EqualSid(expected,
                reinterpret_cast<TOKEN_USER*>(tokenUserBuffer.data())->User.Sid) != FALSE;
            if (sameUser)
            {
                TOKEN_STATISTICS statistics{};
                if (GetTokenInformation(token, TokenStatistics, &statistics,
                                        sizeof(statistics), &bytes))
                {
                    *sessionId = activeSession;
                    *logonId = statistics.AuthenticationId;
                    result = S_OK;
                    CloseHandle(token);
                    CloseHandle(process);
                    break;
                }
                result = HRESULT_FROM_WIN32(GetLastError());
            }
            CloseHandle(token);
            CloseHandle(process);
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    LocalFree(expected);
    return result;
}

static std::wstring RenderQr(const std::string &matrix)
{
    std::vector<std::string> rows;
    std::istringstream input(matrix);
    std::string row;
    while (std::getline(input, row, '/'))
    {
        if (!row.empty()) rows.push_back(row);
    }
    if (rows.empty()) return L"";
    const size_t width = rows.front().size();
    if (!width || width > 100 || rows.size() > 100) return L"";
    for (const auto &r : rows) if (r.size() != width) return L"";
    // Pair two QR rows into one block glyph. Use a light-shade glyph for the
    // white/white case instead of a space: spaces are narrower in LogonUI's
    // proportional font and make the QR columns drift. All four glyphs have
    // the same advance and are emitted as UTF-16 (no console code-page path).
    if (rows.size() % 2) rows.emplace_back(width, '0');
    std::wstring out;
    for (size_t y = 0; y < rows.size(); y += 2)
    {
        for (size_t x = 0; x < width; ++x)
        {
            const bool top = rows[y][x] == '1';
            const bool bottom = rows[y + 1][x] == '1';
            out.push_back(top ? (bottom ? L'\x2588' : L'\x2580')
                              : (bottom ? L'\x2584' : L'\x2591'));
        }
        if (y + 2 < rows.size()) out.append(L"\r\n");
    }
    return out;
}

struct QrViewerWindowSearch
{
    DWORD processId;
    HWND window;
};

static BOOL CALLBACK FindQrViewerWindow(HWND window, LPARAM parameter)
{
    auto *search = reinterpret_cast<QrViewerWindowSearch *>(parameter);
    DWORD processId = 0;
    GetWindowThreadProcessId(window, &processId);
    if (processId != search->processId) return TRUE;

    wchar_t className[64]{};
    if (GetClassNameW(window, className, ARRAYSIZE(className)) > 0 &&
        wcscmp(className, L"ThessleyADQrViewer") == 0 && IsWindowVisible(window))
    {
        search->window = window;
        return FALSE;
    }
    return TRUE;
}

static bool LaunchQrViewer(const std::string &matrix, HWND *viewerWindow,
                           const std::atomic<bool> &cancelled, DWORD *launchError,
                           bool currentDesktop)
{
    if (viewerWindow) *viewerWindow = nullptr;
    if (launchError) *launchError = ERROR_SUCCESS;
    if (matrix.empty() || matrix.size() > 12000)
    {
        if (launchError) *launchError = ERROR_INVALID_DATA;
        return false;
    }
    const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, matrix.data(),
                                           static_cast<int>(matrix.size()), nullptr, 0);
    if (chars <= 0)
    {
        if (launchError) *launchError = ERROR_NO_UNICODE_TRANSLATION;
        return false;
    }
    std::wstring wideMatrix(static_cast<size_t>(chars), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, matrix.data(),
                             static_cast<int>(matrix.size()), wideMatrix.data(), chars))
    {
        if (launchError) *launchError = GetLastError();
        return false;
    }
#ifdef THESSLEY_TICKET_LOGON_TEST
    const std::wstring app = L"C:\\ProgramData\\ThessleyPamWin\\ad-ticket-logon-test\\ThessleyADQrViewer.exe";
#else
    const std::wstring app = L"C:\\ProgramData\\ThessleyPamWin\\ad-credential-provider\\ThessleyADQrViewer-wake-safe.exe";
#endif
    std::wstring command = L"\"" + app + L"\" --matrix=" + wideMatrix;
    std::vector<wchar_t> writable(command.begin(), command.end());
    writable.push_back(L'\0');
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    // Credential UI (mstsc) runs on the caller's interactive desktop. The
    // Winlogon desktop is appropriate only for pre-login and unlock scenarios.
    startup.lpDesktop = currentDesktop
        ? nullptr : const_cast<LPWSTR>(L"WinSta0\\Winlogon");
    PROCESS_INFORMATION process{};
    const BOOL ok = CreateProcessW(app.c_str(), writable.data(), nullptr, nullptr, FALSE,
                                   CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup, &process);
    if (!ok)
    {
        if (launchError) *launchError = GetLastError();
        return false;
    }

    CloseHandle(process.hThread);
    HWND found = nullptr;
    DWORD error = ERROR_TIMEOUT;
    // CreateProcess only means the viewer process was created. Wait for its
    // visible Winlogon-desktop window before claiming that the QR is shown.
    // This avoids the wake/re-enumeration race where cancellation can arrive
    // before the viewer has created a window, leaving either no QR or a stale
    // QR window after the credential is idle.
    for (DWORD waited = 0; waited < 5000 && !cancelled.load(); waited += 100)
    {
        QrViewerWindowSearch search{ process.dwProcessId, nullptr };
        EnumWindows(FindQrViewerWindow, reinterpret_cast<LPARAM>(&search));
        if (search.window)
        {
            found = search.window;
            error = ERROR_SUCCESS;
            break;
        }
        if (WaitForSingleObject(process.hProcess, 0) == WAIT_OBJECT_0)
        {
            DWORD exitCode = ERROR_APP_INIT_FAILURE;
            GetExitCodeProcess(process.hProcess, &exitCode);
            error = exitCode == ERROR_SUCCESS ? ERROR_APP_INIT_FAILURE : exitCode;
            break;
        }
        Sleep(100);
    }

    if (!found)
    {
        if (cancelled.load()) error = ERROR_CANCELLED;
        // The child is our QR viewer and failed to produce a usable window.
        // Do not leave an untracked process/window displaying a stale login QR.
        if (WaitForSingleObject(process.hProcess, 0) != WAIT_OBJECT_0)
            TerminateProcess(process.hProcess, error);
        WaitForSingleObject(process.hProcess, 500);
    }
    else if (viewerWindow)
    {
        *viewerWindow = found;
    }

    CloseHandle(process.hProcess);
    if (launchError) *launchError = error;
    return found != nullptr;
}

static void CloseQrViewer(HWND viewer)
{
    if (viewer && IsWindow(viewer)) PostMessageW(viewer, WM_CLOSE, 0, 0);
}

static std::string JsonString(const std::string &line, const char *key)
{
    const auto keyAt = line.find(key);
    if (keyAt == std::string::npos) return {};
    const auto colon = line.find(':', keyAt + strlen(key));
    if (colon == std::string::npos) return {};
    const auto start = line.find('"', colon + 1);
    if (start == std::string::npos) return {};
    const auto end = line.find('"', start + 1);
    if (end == std::string::npos) return {};
    return line.substr(start + 1, end - start - 1);
}

// RunAgent combines the CLI's stdout and stderr. On failure, retain only a
// short, single-line human diagnostic; never write a successful JSON response
// (which contains the one-time QR link and request identifiers) to the log.
static std::wstring SafeAgentFailureDetail(const std::string &output)
{
    if (output.empty() || output.size() > 4096 || output.find('{') != std::string::npos ||
        output.find("thessleypam:") != std::string::npos ||
        output.find("https:") != std::string::npos ||
        output.find("request_id") != std::string::npos ||
        output.find("qr_matrix") != std::string::npos ||
        output.find("signature") != std::string::npos ||
        output.find("nonce") != std::string::npos ||
        output.find("machine_id") != std::string::npos)
        return L"agent failed; diagnostic suppressed";

    const size_t lineEnd = output.find_first_of("\r\n");
    const size_t length = std::min<size_t>(lineEnd == std::string::npos ? output.size() : lineEnd, 180);
    if (length == 0) return L"agent failed without a diagnostic";
    std::string line = output.substr(0, length);
    for (char &ch : line)
        if (static_cast<unsigned char>(ch) < 0x20 || static_cast<unsigned char>(ch) > 0x7e)
            ch = ' ';
    const int chars = MultiByteToWideChar(CP_UTF8, 0, line.data(),
                                           static_cast<int>(line.size()), nullptr, 0);
    if (chars <= 0) return L"agent failed; diagnostic encoding unavailable";
    std::wstring detail(static_cast<size_t>(chars), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, 0, line.data(), static_cast<int>(line.size()),
                             detail.data(), chars))
        return L"agent failed; diagnostic encoding unavailable";
    return L"agent_error=" + detail;
}

static HRESULT RetrieveKerberosAuthPackage(ULONG *packageId)
{
    if (!packageId) return E_POINTER;
    HANDLE lsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&lsa);
    if (status < 0) return HRESULT_FROM_NT(status);

    LSA_STRING name{};
    name.Buffer = const_cast<PCHAR>(MICROSOFT_KERBEROS_NAME_A);
    name.Length = static_cast<USHORT>(strlen(MICROSOFT_KERBEROS_NAME_A));
    name.MaximumLength = static_cast<USHORT>(name.Length + 1);
    status = LsaLookupAuthenticationPackage(lsa, &name, packageId);
    LsaDeregisterLogonProcess(lsa);
    return status < 0 ? HRESULT_FROM_NT(status) : S_OK;
}

static std::wstring ReadConfiguredAdDefaultDomain()
{
    constexpr wchar_t keyPath[] = L"SOFTWARE\\Thessley\\ADCredentialProvider";
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegGetValueW(HKEY_LOCAL_MACHINE, keyPath, L"DefaultDomain",
                     RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                     &type, nullptr, &bytes) != ERROR_SUCCESS ||
        bytes < sizeof(wchar_t) || bytes > 1024)
        return L"";

    std::vector<wchar_t> value(bytes / sizeof(wchar_t), L'\0');
    if (RegGetValueW(HKEY_LOCAL_MACHINE, keyPath, L"DefaultDomain",
                     RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                     &type, value.data(), &bytes) != ERROR_SUCCESS)
        return L"";
    return std::wstring(value.data());
}

struct PasswordVectorWiper
{
    std::vector<WCHAR> &value;
    ~PasswordVectorWiper() { ThessleySecureClear(value); }
};

CSampleCredential::CSampleCredential():
    _cRef(1),
    _pFTM(nullptr),
    _pCredProvCredentialEvents(nullptr),
    _pProviderEvents(nullptr),
    _providerAdviseContext(0),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fOtherUserTile(false),
    _adLabUser(false),
    _vaultAvailable(false),
    _passwordEntryMode(false),
    _savePasswordAfterSuccess(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0),
    _approvalInProgress(false),
    _approvalCancelled(false),
    _phoneApproved(false),
    _phoneApprovedAt(0)
{
    DllAddRef();
    const HRESULT marshalHr = CoCreateFreeThreadedMarshaler(
        static_cast<ICredentialProviderCredential2 *>(this), &_pFTM);
    ProviderDiag(L"CreateCredentialFTM", marshalHr, 0);

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    _CancelApproval();
    if (_approvalThread.joinable() && _approvalThread.get_id() != std::this_thread::get_id())
    {
        _approvalThread.join();
    }
    ThessleySecureClear(_passwordPendingSave);
    ThessleySecureClear(_pinPendingSave);
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    if (_pProviderEvents) _pProviderEvents->Release();
    if (_pFTM) _pFTM->Release();
    DllRelease();
}

void CSampleCredential::SetProviderEvents(ICredentialProviderEvents *events, UINT_PTR adviseContext)
{
    std::lock_guard<std::mutex> lock(_providerEventsMutex);
    if (events) events->AddRef();
    if (_pProviderEvents) _pProviderEvents->Release();
    _pProviderEvents = events;
    _providerAdviseContext = events ? adviseContext : 0;
}

bool CSampleCredential::IsAutoLogonReady() const
{
#ifdef THESSLEY_TICKET_LOGON_TEST
    return _phoneApproved.load() && !_passwordEntryMode;
#else
    return _phoneApproved.load() && _vaultAvailable && !_passwordEntryMode;
#endif
}

void CSampleCredential::_CancelApproval()
{
    _approvalCancelled.store(true);
}

void CSampleCredential::_StartApproval()
{
    if (_phoneApproved.load()) return;
    bool expected = false;
    if (!_approvalInProgress.compare_exchange_strong(expected, true)) return;

    if (_approvalThread.joinable()) _approvalThread.join();
    _approvalCancelled.store(false);
    _phoneApproved.store(false);
    _phoneApprovedAt.store(0);
    if (_adLabUser && IsPivPhoneTestMode(_adLabVscConfig))
        SetAdLabPivRequestId(_pszUserSid, nullptr);
    ThessleySecureClear(_passwordPendingSave);
    ThessleySecureClear(_pinPendingSave);
    _savePasswordAfterSuccess = false;
    const bool passwordFollowsPhone = _fOtherUserTile ||
        (_adLabUser && IsAdPasswordPlusPhoneTestMode(_adLabVscConfig));
    if (_rgFieldStrings[SFI_EDIT_TEXT])
    {
        SecureZeroMemory(_rgFieldStrings[SFI_EDIT_TEXT], wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) * sizeof(WCHAR));
        CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
        _rgFieldStrings[SFI_EDIT_TEXT] = nullptr;
        SHStrDupW(L"Starting a fresh AD approval request. Keep this tile selected.",
                  &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    if (_rgFieldStrings[SFI_LOGONSTATUS_TEXT])
    {
        CoTaskMemFree(_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        _rgFieldStrings[SFI_LOGONSTATUS_TEXT] = nullptr;
        SHStrDupW(L"Starting phone approval.", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    }
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT, _rgFieldStrings[SFI_EDIT_TEXT]);
        _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, _rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        if (passwordFollowsPhone)
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);
    }
    // The generic domain tile must not retain a password entered before the
    // phone approval. The user enters it only after the one-use approval is
    // granted.
    if (passwordFollowsPhone && _rgFieldStrings[SFI_PASSWORD])
    {
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD],
                         wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        _rgFieldStrings[SFI_PASSWORD] = nullptr;
        SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        if (_pCredProvCredentialEvents && _rgFieldStrings[SFI_PASSWORD])
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD,
                                                       _rgFieldStrings[SFI_PASSWORD]);
    }

    IStream *eventStream = nullptr, *credentialStream = nullptr;
    HRESULT hr = _pCredProvCredentialEvents
        ? CoMarshalInterThreadInterfaceInStream(IID_ICredentialProviderCredentialEvents2,
              _pCredProvCredentialEvents, &eventStream)
        : E_UNEXPECTED;
    ProviderDiag(L"ApprovalMarshalEvents", hr, 0);
    if (SUCCEEDED(hr))
    {
        ICredentialProviderCredential *credential = nullptr;
        hr = QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void **>(&credential));
        if (SUCCEEDED(hr))
        {
            hr = CoMarshalInterThreadInterfaceInStream(IID_ICredentialProviderCredential,
                  credential, &credentialStream);
            credential->Release();
            ProviderDiag(L"ApprovalMarshalCredential", hr, 0);
        }
        else
        {
            ProviderDiag(L"ApprovalQueryCredential", hr, 0);
        }
    }
    if (FAILED(hr))
    {
        _approvalInProgress.store(false);
        if (eventStream) eventStream->Release();
        if (credentialStream) credentialStream->Release();
        if (_rgFieldStrings[SFI_LOGONSTATUS_TEXT])
        {
            CoTaskMemFree(_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            _rgFieldStrings[SFI_LOGONSTATUS_TEXT] = nullptr;
            SHStrDupW(L"Could not start phone approval. Choose PIN or retry.", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
        if (_pCredProvCredentialEvents)
            _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT, _rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        return;
    }

    IStream *providerEventsStream = nullptr;
    UINT_PTR providerAdviseContext = 0;
    if ((_vaultAvailable || (_adLabUser && IsTicketLogonTestMode(_adLabVscConfig))) &&
        !_passwordEntryMode)
    {
        std::lock_guard<std::mutex> lock(_providerEventsMutex);
        if (_pProviderEvents)
        {
            providerAdviseContext = _providerAdviseContext;
            const HRESULT notifyHr = CoMarshalInterThreadInterfaceInStream(
                IID_ICredentialProviderEvents, _pProviderEvents, &providerEventsStream);
            ProviderDiag(L"ApprovalMarshalProviderEvents", notifyHr, 0);
        }
    }

    AddRef();
    try
    {
        _approvalThread = std::thread([this, eventStream, credentialStream,
                                       providerEventsStream, providerAdviseContext]()
        {
            CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            ICredentialProviderCredentialEvents2 *events = nullptr;
            ICredentialProviderCredential *credential = nullptr;
            ICredentialProviderEvents *providerEvents = nullptr;
            CoGetInterfaceAndReleaseStream(eventStream, IID_ICredentialProviderCredentialEvents2,
                                           reinterpret_cast<void **>(&events));
            CoGetInterfaceAndReleaseStream(credentialStream, IID_ICredentialProviderCredential,
                                           reinterpret_cast<void **>(&credential));
            if (providerEventsStream)
                CoGetInterfaceAndReleaseStream(providerEventsStream, IID_ICredentialProviderEvents,
                                               reinterpret_cast<void **>(&providerEvents));
            auto update = [&](DWORD field, const std::wstring &value)
            {
                if (!_approvalCancelled.load() && events && credential)
                    events->SetFieldString(credential, field, value.c_str());
            };
            bool ok = false;
            const PCWSTR context = _cpus == CPUS_UNLOCK_WORKSTATION ? L"unlock" : L"interactive";
            const bool pivSigning = _adLabUser && IsPivPhoneTestMode(_adLabVscConfig) &&
                _cpus == CPUS_LOGON;
            std::string started;
            HRESULT agentHr = _fOtherUserTile
                ? StartAdApprovalForAccount(_pszQualifiedUserName, context,
                                            _approvalCancelled, &started)
                : StartAdApprovalForSid(_pszUserSid, context,
                                        _approvalCancelled, &started, pivSigning);
            std::string requestId = SUCCEEDED(agentHr)
                ? JsonString(started, "\"request_id\"") : std::string();
            std::string credentialMethod = SUCCEEDED(agentHr)
                ? JsonString(started, "\"credential_method\"") : std::string();
            std::string matrix = SUCCEEDED(agentHr)
                ? JsonString(started, "\"qr_matrix\"") : std::string();
            // The local AD agent already rejects unsupported policy methods
            // before it emits JSON. Keep this extra check on the established
            // VSC provider, but do not let a second native JSON parse suppress
            // the isolated ticket-test QR after the agent has accepted it.
#ifndef THESSLEY_TICKET_LOGON_TEST
            if (SUCCEEDED(agentHr) && credentialMethod != "tpm_smartcard")
                agentHr = E_ACCESSDENIED;
#endif
            const std::wstring failureDetail = FAILED(agentHr)
                ? SafeAgentFailureDetail(started) : L"QR matrix received; contents omitted";
            ProviderDiag(L"ADApprovalStart", agentHr,
                         static_cast<DWORD>(std::min<size_t>(started.size(), MAXDWORD)),
                         FAILED(agentHr) ? failureDetail.c_str()
                                         : (matrix.empty() ? L"QR matrix missing" : failureDetail.c_str()));
            ClearAdApprovalOutput(&started);

            std::wstring wideRequestId;
            if (!requestId.empty() && requestId.size() <= 128 &&
                std::all_of(requestId.begin(), requestId.end(), [](unsigned char c)
                    { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                             (c >= '0' && c <= '9') || c == '_' || c == '-'; }))
                wideRequestId.assign(requestId.begin(), requestId.end());
            else
                agentHr = E_INVALIDARG;

            bool pivRequestStored = false;
            if (SUCCEEDED(agentHr) && !_approvalCancelled.load() && pivSigning)
            {
                pivRequestStored = SetAdLabPivRequestId(_pszUserSid, wideRequestId.c_str());
                if (!pivRequestStored)
                {
                    agentHr = E_ACCESSDENIED;
                    ProviderDiag(L"StorePendingPivPhoneRequestId", agentHr, 0,
                                 L"could not publish the one-use pending request id");
                }
                else
                {
                    ProviderDiag(L"PendingPivPhoneRequestIdReady", S_OK, 0,
                                 L"one-use id available; no QR or credential data logged");
                }
            }

            bool qrViewerFailed = false;
            if (SUCCEEDED(agentHr) && !_approvalCancelled.load() && !matrix.empty())
            {
                HWND qrViewer = nullptr;
                DWORD viewerError = ERROR_SUCCESS;
                bool viewerStarted = LaunchQrViewer(matrix, &qrViewer,
                    _approvalCancelled, &viewerError, _cpus == CPUS_CREDUI);
                if (!viewerStarted && !_approvalCancelled.load())
                {
                    ProviderDiag(L"ADApprovalQrViewerRetry",
                                 HRESULT_FROM_WIN32(viewerError), 1,
                                 L"first viewer attempt did not produce a visible window");
                    Sleep(350);
                    if (!_approvalCancelled.load())
                        viewerStarted = LaunchQrViewer(matrix, &qrViewer,
                            _approvalCancelled, &viewerError, _cpus == CPUS_CREDUI);
                }
                ProviderDiag(L"ADApprovalQrViewer",
                    viewerStarted ? S_OK : HRESULT_FROM_WIN32(viewerError),
                    static_cast<DWORD>(std::min<size_t>(matrix.size(), MAXDWORD)),
                    viewerStarted ? L"visible QR window confirmed on Winlogon desktop"
                                  : L"viewer did not produce a visible window; launch error recorded");
                if (viewerStarted)
                {
                    update(SFI_EDIT_TEXT, pivSigning
                        ? L"Approve on your phone, then submit this tile for its exact PIV signature."
                        : L"Scan and approve on your phone.");
                    update(SFI_LOGONSTATUS_TEXT, pivSigning
                        ? L"Waiting for phone approval and the matching Windows PIV request."
                        : L"Waiting for phone approval.");
                    std::string result;
                    agentHr = PollAdApproval(wideRequestId.c_str(), 175,
                                             _approvalCancelled, &result);
                    ok = SUCCEEDED(agentHr) && JsonString(result, "\"status\"") == "approved";
                    ClearAdApprovalOutput(&result);
                }
                else
                {
                    agentHr = HRESULT_FROM_WIN32(viewerError == ERROR_SUCCESS
                        ? ERROR_CANCELLED : viewerError);
                    qrViewerFailed = true;
                }
                CloseQrViewer(qrViewer);
            }
            else if (SUCCEEDED(agentHr))
            {
                ProviderDiag(L"ADApprovalQrMissing", E_FAIL, 0,
                             L"approval response did not contain a QR matrix");
                agentHr = E_FAIL;
            }
            if (FAILED(agentHr) && !_approvalCancelled.load())
                update(SFI_LOGONSTATUS_TEXT, qrViewerFailed
                    ? L"The approval QR window did not appear. Select this tile to retry."
                    : L"Could not start phone approval. Check network access and retry.");
            ClearAdApprovalOutput(&started);
            if ((!ok || _approvalCancelled.load()) && pivRequestStored)
            {
                SetAdLabPivRequestId(_pszUserSid, nullptr);
                ProviderDiag(L"ClearPendingPivPhoneRequestId", S_OK, 0,
                             L"request ended before approval; one-use id cleared");
            }
            if (ok && !_approvalCancelled.load())
            {
                _phoneApprovedAt.store(GetTickCount64());
                _phoneApproved.store(true);
                const bool passwordFollowsPhone = _fOtherUserTile ||
                    (_adLabUser && IsAdPasswordPlusPhoneTestMode(_adLabVscConfig));
                update(SFI_LOGONSTATUS_TEXT, pivSigning
                    ? L"Phone signed this PIV login. Windows is checking it."
                    : (IsAutoLogonReady() && providerEvents
                        ? L"Phone approved. Signing in..."
                        : (passwordFollowsPhone
                            ? L"Phone approved. Enter the Windows password and submit."
                            : L"Phone approved. Select Submit to sign in.")));
                if (passwordFollowsPhone && events && credential)
                {
                    const HRESULT showPasswordHr = events->SetFieldState(
                        credential, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
                    ProviderDiag(L"OtherUserShowPasswordAfterApproval", showPasswordHr, 0,
                                 L"password field revealed only after phone approval");
                }
                if (IsAutoLogonReady() && providerEvents)
                {
                    const HRESULT changedHr = providerEvents->CredentialsChanged(providerAdviseContext);
                    ProviderDiag(L"ApprovalCredentialsChanged", changedHr, 0);
                }
            }
            else if (!_approvalCancelled.load())
            {
                update(SFI_LOGONSTATUS_TEXT, L"Approval failed or expired. Select again to retry, or choose PIN.");
            }
            _approvalInProgress.store(false);
            ProviderDiag(L"ApprovalWorkerFinished", ok ? S_OK : E_ABORT, 0);
            if (credential) credential->Release();
            if (events) events->Release();
            if (providerEvents) providerEvents->Release();
            CoUninitialize();
            if (!QueueUserWorkItem(ReleaseCredentialReference, this, WT_EXECUTEDEFAULT))
            {
                // A rare pool-queue failure must not destroy this object on its
                // own joinable thread. Keep the reference rather than crashing
                // the Windows sign-in process; diagnostics make the leak visible.
                ProviderDiag(L"QueueCredentialRelease", HRESULT_FROM_WIN32(GetLastError()), 0);
            }
        });
    }
    catch (...)
    {
        _approvalInProgress.store(false);
        eventStream->Release();
        credentialStream->Release();
        if (providerEventsStream) providerEventsStream->Release();
        Release();
        _CancelApproval();
    }
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    if (pcpUser)
    {
        GUID guidProvider{};
        const HRESULT providerHr = pcpUser->GetProviderID(&guidProvider);
        if (FAILED(providerHr)) return providerHr;
        _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);
    }

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Thessley AD Passkey", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Thessley AD Passkey", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Scan and approve on your phone. First setup may ask for the card PIN once.", &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Select this tile to request phone approval.", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Save encrypted password for QR-only sign-in", &_rgFieldStrings[SFI_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Combobox", &_rgFieldStrings[SFI_COMBOBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Launch helper window", &_rgFieldStrings[SFI_LAUNCHWINDOW_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Hide additional controls", &_rgFieldStrings[SFI_HIDECONTROLS_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Set up QR-only sign-in (one-time Windows password)",
                       &_rgFieldStrings[SFI_QR_SETUP_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_DOMAINNAME]);
    }
    if (SUCCEEDED(hr) && !pcpUser)
    {
        _fOtherUserTile = true;
        _adLabUser = true;
        _passwordEntryMode = true;
        _adLabVscConfig.passwordPlusPhoneTest = true;
        hr = SHStrDupW(L"", &_pszQualifiedUserName);
        if (FAILED(hr)) return hr;
        const bool credUi = cpus == CPUS_CREDUI;
        hr = SHStrDupW(credUi ? L"RDP sign-in" : L"Other user",
                       &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        if (SUCCEEDED(hr)) hr = SHStrDupW(credUi ? L"Remote desktop" : L"Domain sign-in",
                                           &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        if (SUCCEEDED(hr)) hr = SHStrDupW(
            credUi ? L"Enter your domain account, approve on your phone, then enter your password."
                   : L"Enter a domain account and request phone approval.",
            &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        if (SUCCEEDED(hr)) {
            if (_rgFieldStrings[SFI_LABEL]) CoTaskMemFree(_rgFieldStrings[SFI_LABEL]);
            _rgFieldStrings[SFI_LABEL] = nullptr;
            hr = SHStrDupW(L"Thessley Passkey",
                           &_rgFieldStrings[SFI_LABEL]);
        }
        if (SUCCEEDED(hr)) {
            if (_rgFieldStrings[SFI_LARGE_TEXT]) CoTaskMemFree(_rgFieldStrings[SFI_LARGE_TEXT]);
            _rgFieldStrings[SFI_LARGE_TEXT] = nullptr;
            hr = SHStrDupW(L"Thessley Passkey",
                           &_rgFieldStrings[SFI_LARGE_TEXT]);
        }
        if (SUCCEEDED(hr)) {
            if (_rgFieldStrings[SFI_QR_SETUP_LINK]) CoTaskMemFree(_rgFieldStrings[SFI_QR_SETUP_LINK]);
            _rgFieldStrings[SFI_QR_SETUP_LINK] = nullptr;
            hr = SHStrDupW(L"Request phone approval", &_rgFieldStrings[SFI_QR_SETUP_LINK]);
        }
        if (SUCCEEDED(hr)) {
            const std::wstring defaultDomain = ReadConfiguredAdDefaultDomain();
            if (!defaultDomain.empty()) {
                CoTaskMemFree(_rgFieldStrings[SFI_DOMAINNAME]);
                _rgFieldStrings[SFI_DOMAINNAME] = nullptr;
                hr = SHStrDupW(defaultDomain.c_str(), &_rgFieldStrings[SFI_DOMAINNAME]);
            }
            _rgFieldStatePairs[SFI_USERNAME].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_USERNAME].cpfis = CPFIS_FOCUSED;
            _rgFieldStatePairs[SFI_DOMAINNAME].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_DOMAINNAME].cpfis = CPFIS_NONE;
            _rgFieldStatePairs[SFI_PASSWORD].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_PASSWORD].cpfis = CPFIS_NONE;
            _rgFieldStatePairs[SFI_QR_SETUP_LINK].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_LOGONSTATUS_TEXT].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            _rgFieldStatePairs[SFI_FULLNAME_TEXT].cpfs = CPFS_HIDDEN;
            _rgFieldStatePairs[SFI_DISPLAYNAME_TEXT].cpfs = CPFS_HIDDEN;
            _rgFieldStatePairs[SFI_SUBMIT_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        }
        return hr;
    }
    if (!pcpUser) return hr;
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszUserName;
        pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
        if (pszUserName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
            CoTaskMemFree(pszUserName);
        }
        else
        {
            hr =  SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszDisplayName;
        pcpUser->GetStringValue(PKEY_Identity_DisplayName, &pszDisplayName);
        if (pszDisplayName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Display Name: %s", pszDisplayName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
            CoTaskMemFree(pszDisplayName);
        }
        else
        {
            hr = SHStrDupW(L"Display Name is NULL", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszLogonStatus;
        pcpUser->GetStringValue(PKEY_Identity_LogonStatusString, &pszLogonStatus);
        if (pszLogonStatus != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Logon Status: %s", pszLogonStatus);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            CoTaskMemFree(pszLogonStatus);
        }
        else
        {
            hr = SHStrDupW(L"", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
    }

    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }
    if (SUCCEEDED(hr))
    {
        _fIsLocalUser = IsLocalSamAccountSid(_pszUserSid);
        ProviderDiag(L"LocalSamSidCheck", S_OK, _fIsLocalUser ? 1 : 0,
                     L"identity is classified from the local SAM SID prefix");
        const bool adLabConfigLoaded = LoadAdLabVscConfig(_pszUserSid, &_adLabVscConfig);
        bool isAllowedAdLabUser = false;
#ifdef THESSLEY_TICKET_LOGON_TEST
        isAllowedAdLabUser = adLabConfigLoaded;
        ProviderDiag(L"TicketConfigRead", S_OK, isAllowedAdLabUser ? 1 : 0,
            _adLabVscConfig.ticketLogonTest ? L"ticket-flag=1" : L"ticket-flag=0");
        isAllowedAdLabUser = isAllowedAdLabUser &&
            (_adLabVscConfig.ticketLogonTest || IsPivPhoneTestMode(_adLabVscConfig));
#else
        if (!_fIsLocalUser && !adLabConfigLoaded)
        {
            // Named domain accounts get the same username-first, phone-then-
            // password flow as Other user. The AD service still authorizes
            // the SID before it creates an approval request; this only makes
            // the named tile available without per-PC enrollment state.
            _adLabVscConfig.passwordPlusPhoneTest = true;
            isAllowedAdLabUser = true;
        }
        else
        {
            // Ticket-test-only SIDs never appear on the established VSC tile.
            isAllowedAdLabUser = adLabConfigLoaded &&
                (IsPivPhoneTestMode(_adLabVscConfig) ||
                 IsAdPasswordPlusPhoneTestMode(_adLabVscConfig) ||
                 (!_adLabVscConfig.providerName.empty() &&
                  (_adLabVscConfig.keySpec == AT_KEYEXCHANGE ||
                   _adLabVscConfig.keySpec == AT_SIGNATURE)));
        }
#endif
        wchar_t adLabIdentityDetail[512]{};
        StringCchPrintfW(adLabIdentityDetail, ARRAYSIZE(adLabIdentityDetail),
            L"sid=%s config=%u piv=%u password_plus_phone=%u ticket=%u keySpec=%lu",
            _pszUserSid ? _pszUserSid : L"(null)",
            adLabConfigLoaded ? 1u : 0u,
            _adLabVscConfig.pivPhoneSigning ? 1u : 0u,
            _adLabVscConfig.passwordPlusPhoneTest ? 1u : 0u,
            _adLabVscConfig.ticketLogonTest ? 1u : 0u,
            static_cast<unsigned long>(_adLabVscConfig.pivKeySpec));
        ProviderDiag(L"AdLabSidCheck", S_OK, isAllowedAdLabUser ? 1 : 0,
                     adLabIdentityDetail);
        ProviderDiag(L"IdentityLocalProvider", S_OK, _fIsLocalUser ? 1 : 0,
                     L"SID-based local/domain classification");
        if (!isAllowedAdLabUser && !_fIsLocalUser)
        {
            hr = E_ACCESSDENIED;
        }
        else
        {
            if (_fIsLocalUser)
            {
                // The local recovery route stays inside this provider when the
                // Windows Password provider is excluded by machine policy.
                _adLabUser = false;
                _vaultAvailable = false;
                _passwordEntryMode = true;
            }
            else
            {
                _fIsLocalUser = false;
                _adLabUser = true;
                _vaultAvailable = !IsTicketLogonTestMode(_adLabVscConfig) &&
                    !IsAdPasswordPlusPhoneTestMode(_adLabVscConfig) &&
                    ThessleyPinVaultExists(_pszUserSid);
                _passwordEntryMode = !IsTicketLogonTestMode(_adLabVscConfig) &&
                    (IsAdPasswordPlusPhoneTestMode(_adLabVscConfig) || !_vaultAvailable);
            }
            _fChecked = false;
            if (IsPivPhoneTestMode(_adLabVscConfig))
            {
                // Keep the isolated PIV test visibly distinct from the regular
                // Thessley AD phone-approval tile.
                if (_rgFieldStrings[SFI_LABEL]) CoTaskMemFree(_rgFieldStrings[SFI_LABEL]);
                _rgFieldStrings[SFI_LABEL] = nullptr;
                SHStrDupW(L"Phone test: scan QR code", &_rgFieldStrings[SFI_LABEL]);
                if (_rgFieldStrings[SFI_LARGE_TEXT]) CoTaskMemFree(_rgFieldStrings[SFI_LARGE_TEXT]);
                _rgFieldStrings[SFI_LARGE_TEXT] = nullptr;
                SHStrDupW(L"Phone test: scan QR code", &_rgFieldStrings[SFI_LARGE_TEXT]);
            }
            if (_rgFieldStrings[SFI_EDIT_TEXT])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_EDIT_TEXT], wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
            }
            _rgFieldStrings[SFI_EDIT_TEXT] = nullptr;
            SHStrDupW(IsTicketLogonTestMode(_adLabVscConfig)
                ? L"Ticket-logon feasibility test: phone approval submits one short-lived, local-only Kerberos ticket."
                : (IsAdPasswordPlusPhoneTestMode(_adLabVscConfig)
                    ? L"Select Request phone approval to show a QR. Then enter your Windows password."
                    : (IsPivPhoneTestMode(_adLabVscConfig)
                            ? (_vaultAvailable
                                ? L"Your phone signs each Windows PIV login. The AD key stays on your phone."
                                : L"Approve on your phone and enter the disposable PIV test PIN for this lab.")
                        : (_vaultAvailable
                            ? L"Phone approval will unlock this PC's TPM sign-in key."
                            : L"For the first sign-in, enter the TPM PIN once. Check Remember to use QR approval alone next time."))),
                &_rgFieldStrings[SFI_EDIT_TEXT]);
            if (_fIsLocalUser && _rgFieldStrings[SFI_EDIT_TEXT])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_EDIT_TEXT],
                    wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
                _rgFieldStrings[SFI_EDIT_TEXT] = nullptr;
                SHStrDupW(L"Local recovery account. Enter its Windows password.",
                          &_rgFieldStrings[SFI_EDIT_TEXT]);
            }
            if (IsTicketLogonTestMode(_adLabVscConfig) ||
                IsAdPasswordPlusPhoneTestMode(_adLabVscConfig))
            {
                if (_rgFieldStrings[SFI_LARGE_TEXT]) CoTaskMemFree(_rgFieldStrings[SFI_LARGE_TEXT]);
                _rgFieldStrings[SFI_LARGE_TEXT] = nullptr;
                SHStrDupW(IsTicketLogonTestMode(_adLabVscConfig)
                    ? L"Thessley AD Ticket Test (Clone 1 only)"
                    : L"Thessley AD Passkey",
                          &_rgFieldStrings[SFI_LARGE_TEXT]);
            }
            if ((IsAdPasswordPlusPhoneTestMode(_adLabVscConfig) ||
                 IsPivPhoneTestMode(_adLabVscConfig)) &&
                _rgFieldStrings[SFI_QR_SETUP_LINK])
            {
                CoTaskMemFree(_rgFieldStrings[SFI_QR_SETUP_LINK]);
                _rgFieldStrings[SFI_QR_SETUP_LINK] = nullptr;
                SHStrDupW(L"Request phone approval", &_rgFieldStrings[SFI_QR_SETUP_LINK]);
            }
            if (_rgFieldStrings[SFI_CHECKBOX]) CoTaskMemFree(_rgFieldStrings[SFI_CHECKBOX]);
            _rgFieldStrings[SFI_CHECKBOX] = nullptr;
            SHStrDupW(IsTicketLogonTestMode(_adLabVscConfig)
                ? L"Ticket test (no PIN or password is sent)"
                : (IsAdPasswordPlusPhoneTestMode(_adLabVscConfig)
                    ? L"Password is never saved"
                    : (IsPivPhoneTestMode(_adLabVscConfig)
                        ? L"Remember PIV test PIN on this PC (encrypted)"
                        : L"Remember TPM PIN on this PC for QR-only sign-in (encrypted)")),
                &_rgFieldStrings[SFI_CHECKBOX]);
        }
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    const HRESULT hr = pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
    ProviderDiag(L"CredentialAdviseEvents2", hr, 0);
    return hr;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    ProviderDiag(L"CredentialSetSelected", S_OK, 0);
    // LogonUI may select the default credential while the workstation is
    // idle or waking. Require an explicit command-link click before showing a
    // QR or creating a phone approval request.
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    _CancelApproval();
    if (_approvalThread.joinable() && _approvalThread.get_id() != std::this_thread::get_id())
    {
        _approvalThread.join();
    }
    _phoneApproved.store(false);
    _phoneApprovedAt.store(0);
    if (_rgFieldStrings[SFI_EDIT_TEXT])
    {
        SecureZeroMemory(_rgFieldStrings[SFI_EDIT_TEXT], wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) * sizeof(WCHAR));
        CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
        hr = SHStrDupW(L"Select this tile to request a fresh AD approval.", &_rgFieldStrings[SFI_EDIT_TEXT]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT, _rgFieldStrings[SFI_EDIT_TEXT]);
        }
    }
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        if ((dwFieldID == SFI_USERNAME || dwFieldID == SFI_DOMAINNAME) && !_fOtherUserTile)
        {
            *pcpfs = CPFS_HIDDEN;
            *pcpfis = CPFIS_NONE;
        }
        else if (dwFieldID == SFI_USERNAME && _fOtherUserTile)
        {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = CPFIS_FOCUSED;
        }
        else if (dwFieldID == SFI_DOMAINNAME && _fOtherUserTile)
        {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = CPFIS_NONE;
        }
        else if (dwFieldID == SFI_PASSWORD)
        {
            *pcpfs = (_fOtherUserTile ||
                      (_adLabUser && IsAdPasswordPlusPhoneTestMode(_adLabVscConfig)))
                ? (_phoneApproved.load() ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN)
                : ((_adLabUser && (!_passwordEntryMode ||
                                     IsTicketLogonTestMode(_adLabVscConfig)))
                    ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE);
            *pcpfis = CPFIS_FOCUSED;
        }
        else if (dwFieldID == SFI_CHECKBOX && !_adLabUser)
            *pcpfs = CPFS_HIDDEN; // Local accounts never expose the AD card-PIN option.
        else if (dwFieldID == SFI_CHECKBOX && _adLabUser)
            *pcpfs = IsAdPasswordPlusPhoneTestMode(_adLabVscConfig)
                ? CPFS_HIDDEN
                : (_passwordEntryMode
                    ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
        else if (dwFieldID == SFI_QR_SETUP_LINK && _fOtherUserTile)
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        else if (dwFieldID == SFI_QR_SETUP_LINK && _adLabUser &&
                 (IsAdPasswordPlusPhoneTestMode(_adLabVscConfig) ||
                  IsPivPhoneTestMode(_adLabVscConfig)))
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        else if (dwFieldID == SFI_QR_SETUP_LINK &&
                 (!_adLabUser || IsTicketLogonTestMode(_adLabVscConfig) || IsPivPhoneTestMode(_adLabVscConfig) ||
                  IsAdPasswordPlusPhoneTestMode(_adLabVscConfig)))
            *pcpfs = CPFS_HIDDEN;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    *phbmp = nullptr;
    HRESULT hr = E_INVALIDARG;

    if (SFI_TILEIMAGE == dwFieldID)
    {
        // Load the RT_BITMAP resource directly. LoadImage/LoadBitmap reject
        // this V4 header in LogonUI on some Windows 11 builds.
        HRSRC resource = FindResourceW(HINST_THISDLL,
                                       MAKEINTRESOURCEW(IDB_TILE_IMAGE), RT_BITMAP);
        const DWORD resourceSize = resource ? SizeofResource(HINST_THISDLL, resource) : 0;
        HGLOBAL loaded = resource ? LoadResource(HINST_THISDLL, resource) : nullptr;
        const auto *header = loaded
            ? static_cast<const BITMAPV4HEADER *>(LockResource(loaded)) : nullptr;

        if (header && resourceSize >= sizeof(BITMAPV4HEADER) &&
            header->bV4Size == sizeof(BITMAPV4HEADER) &&
            header->bV4Width > 0 && header->bV4Width <= 512 &&
            header->bV4Height != 0 && header->bV4Height >= -512 && header->bV4Height <= 512 &&
            header->bV4BitCount == 32 && header->bV4V4Compression == BI_BITFIELDS &&
            header->bV4AlphaMask != 0 && header->bV4SizeImage != 0 &&
            static_cast<ULONGLONG>(header->bV4Size) + header->bV4SizeImage <= resourceSize)
        {
            void *pixels = nullptr;
            HDC screen = GetDC(nullptr);
            HBITMAP bitmap = screen ? CreateDIBSection(
                screen, reinterpret_cast<const BITMAPINFO *>(header), DIB_RGB_COLORS,
                &pixels, nullptr, 0) : nullptr;
            if (screen) ReleaseDC(nullptr, screen);

            if (bitmap && pixels)
            {
                CopyMemory(pixels,
                           reinterpret_cast<const BYTE *>(header) + header->bV4Size,
                           header->bV4SizeImage);
                *phbmp = bitmap;
                hr = S_OK;
            }
            else
            {
                if (bitmap) DeleteObject(bitmap);
                hr = HRESULT_FROM_WIN32(GetLastError());
            }
        }
        else
        {
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
    }

    ProviderDiag(L"GetBitmapValue", hr, dwFieldID);
    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        // The password field is hidden during QR-only sign-in. Keep Submit
        // beside the always-visible status field so LogonUI does not hide it.
        *pdwAdjacentTo = SFI_LOGONSTATUS_TEXT;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
void CSampleCredential::_ResetApprovalForIdentityChange()
{
    _CancelApproval();
    _phoneApproved.store(false);
    _phoneApprovedAt.store(0);
    if (_approvalThread.joinable() &&
        _approvalThread.get_id() != std::this_thread::get_id())
        _approvalThread.join();
    _approvalInProgress.store(false);
}

HRESULT CSampleCredential::_RefreshOtherUserQualifiedName()
{
    const PCWSTR user = _rgFieldStrings[SFI_USERNAME];
    const PCWSTR domain = _rgFieldStrings[SFI_DOMAINNAME];
    std::wstring qualified;
    if (user && user[0] && domain && domain[0] &&
        !wcschr(user, L'\\') && !wcschr(user, L'/') &&
        !wcschr(domain, L'\\') && !wcschr(domain, L'/'))
    {
        qualified.assign(domain);
        qualified.push_back(L'\\');
        qualified.append(user);
    }

    PWSTR replacement = nullptr;
    const HRESULT hr = SHStrDupW(qualified.c_str(), &replacement);
    if (SUCCEEDED(hr))
    {
        CoTaskMemFree(_pszQualifiedUserName);
        _pszQualifiedUserName = replacement;
    }
    return hr;
}

HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        const bool identityField = dwFieldID == SFI_USERNAME || dwFieldID == SFI_DOMAINNAME;
        if (_fOtherUserTile && identityField &&
            (!pwz || wcslen(pwz) > 128 || wcschr(pwz, L'\\') || wcschr(pwz, L'/')))
            return E_INVALIDARG;
        const bool identityChanged = _fOtherUserTile && identityField &&
            *ppwszStored && wcscmp(*ppwszStored, pwz) != 0;
        if (identityChanged)
            _ResetApprovalForIdentityChange();
        if (dwFieldID == SFI_PASSWORD && *ppwszStored)
            SecureZeroMemory(*ppwszStored, wcslen(*ppwszStored) * sizeof(WCHAR));
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
        if (SUCCEEDED(hr) && identityField && _fOtherUserTile)
            hr = _RefreshOtherUserQualifiedName();
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr;
    *ppwszLabel = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    if (!_fIsLocalUser && !_adLabUser)
        return E_ACCESSDENIED;
    if (_adLabUser && IsAdPasswordPlusPhoneTestMode(_adLabVscConfig))
        return E_ACCESSDENIED;
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        _savePasswordAfterSuccess = _passwordEntryMode && bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    if (!_fIsLocalUser && !_adLabUser)
        return E_ACCESSDENIED; // Reject identities outside the local and allowlisted AD flows.
    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
        case SFI_LAUNCHWINDOW_LINK:
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

            // Pop a messagebox indicating the click.
            ::MessageBox(hwndOwner, L"Command link clicked", L"Click!", 0);
            break;
        case SFI_HIDECONTROLS_LINK:
            _pCredProvCredentialEvents->BeginFieldUpdates();
            cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FULLNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_DISPLAYNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LOGONSTATUS_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_CHECKBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_EDIT_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_COMBOBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_HIDECONTROLS_LINK, _fShowControls? L"Hide additional controls" : L"Show additional controls");
            _pCredProvCredentialEvents->EndFieldUpdates();
            _fShowControls = !_fShowControls;
            break;
        case SFI_QR_SETUP_LINK:
            if (_fOtherUserTile)
            {
                ProviderDiag(L"OtherUserApprovalLinkClicked", S_OK, dwFieldID,
                             L"account text and QR payload omitted");
                if (!_pszQualifiedUserName || !_pszQualifiedUserName[0])
                {
            if (_pCredProvCredentialEvents)
                _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT,
                    L"Enter both your username and domain first.");
                    return S_OK;
                }
                _StartApproval();
                break;
            }
            if (_adLabUser)
            {
                if (IsAdPasswordPlusPhoneTestMode(_adLabVscConfig) ||
                    IsPivPhoneTestMode(_adLabVscConfig))
                {
                    _StartApproval();
                    break;
                }
                if (IsTicketLogonTestMode(_adLabVscConfig))
                    return E_ACCESSDENIED;
                _passwordEntryMode = !_passwordEntryMode;
                _fChecked = _passwordEntryMode;
                _savePasswordAfterSuccess = false;
                if (_pCredProvCredentialEvents)
                {
                    _pCredProvCredentialEvents->BeginFieldUpdates();
                    _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD,
                        _passwordEntryMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
                    _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX,
                        _passwordEntryMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
                    _pCredProvCredentialEvents->SetFieldCheckbox(this, SFI_CHECKBOX, _fChecked,
                        L"Remember TPM card PIN on this PC for QR-only sign-in (encrypted)");
                    _pCredProvCredentialEvents->SetFieldString(this, SFI_QR_SETUP_LINK,
                        _passwordEntryMode ? L"Cancel PIN setup" : L"Set up QR-only sign-in");
                    _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT,
                        _passwordEntryMode
                            ? L"Enter the card PIN once. Check Remember; after successful sign-in, future logins use phone approval only."
                            : L"Approve this sign-in on your phone.");
                    _pCredProvCredentialEvents->EndFieldUpdates();
                }
                break;
            }
            _passwordEntryMode = !_passwordEntryMode;
            _savePasswordAfterSuccess = _passwordEntryMode && _fChecked;
            _fChecked = _passwordEntryMode;
            if (!_passwordEntryMode && _rgFieldStrings[SFI_PASSWORD])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD],
                                 wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
                _rgFieldStrings[SFI_PASSWORD] = nullptr;
                SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
            }
            if (_pCredProvCredentialEvents)
            {
            _pCredProvCredentialEvents->BeginFieldUpdates();
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD,
                _passwordEntryMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX,
                _passwordEntryMode ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldCheckbox(this, SFI_CHECKBOX, _fChecked,
                L"Save encrypted password for QR-only sign-in");
            _pCredProvCredentialEvents->SetFieldString(this, SFI_QR_SETUP_LINK,
                _passwordEntryMode ? L"Cancel password setup" :
                    (_vaultAvailable ? L"Update saved QR sign-in" :
                                       L"Set up QR-only sign-in (one-time Windows password)"));
            _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT,
                _passwordEntryMode
                    ? L"Enter the Windows password once. After a successful sign-in it is encrypted on this PC; future sign-ins use phone approval."
                    : L"Approve this sign-in with Thessley Passkey.");
            _pCredProvCredentialEvents->EndFieldUpdates();
            }
            break;
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // The phone approval is a short-lived, one-use gate. Keep the built-in Windows PIN/password tiles separate.
    if (_phoneApproved.load())
    {
        const ULONGLONG approvedAt = _phoneApprovedAt.load();
        if (approvedAt == 0 || GetTickCount64() - approvedAt > 120000)
        {
            _phoneApproved.store(false);
            _phoneApprovedAt.store(0);
        }
    }
    std::wstring pendingPivRequestId;
    const bool pendingPivMaySubmit = _adLabUser && IsPivPhoneTestMode(_adLabVscConfig) &&
        _cpus == CPUS_LOGON && GetAdLabPivRequestId(_pszUserSid, &pendingPivRequestId);
    if (_adLabUser && !_phoneApproved.load() && !pendingPivMaySubmit)
    {
        // On the username-first Other user tile, pressing Submit is also a
        // clear way to start the phone step. It never serializes credentials
        // before approval; it only launches the same approval flow as the
        // Request phone approval link.
        const bool passwordFirstFlow = _fOtherUserTile ||
            (_adLabUser && IsAdPasswordPlusPhoneTestMode(_adLabVscConfig));
        if (passwordFirstFlow)
        {
            if (_fOtherUserTile && (!_pszQualifiedUserName || !_pszQualifiedUserName[0]))
            {
                SHStrDupW(L"Enter your username and domain, then request phone approval.",
                          ppwszOptionalStatusText);
                *pcpsiOptionalStatusIcon = CPSI_WARNING;
                return S_OK;
            }
            ProviderDiag(L"PasswordFirstSubmitStartsApproval", S_OK, 0,
                         L"submit starts phone approval; credentials not serialized");
            _StartApproval();
            SHStrDupW(L"Phone approval started. Scan the QR; then enter the Windows password and submit again.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_OK;
        }
        SHStrDupW(L"Approve this sign-in with Thessley Passkey first, or choose another Windows sign-in option.",
                  ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_OK;
    }

    // The normal certificate mode never serializes an account password. The
    // explicit password-plus-phone test below is the sole exception: it sends
    // the typed password through Windows' standard interactive logon path and
    // never persists it.
    if (_adLabUser)
    {
        if (IsTicketLogonTestMode(_adLabVscConfig))
        {
            _phoneApproved.store(false); // ticket handoff is always one-use
            _phoneApprovedAt.store(0);
            std::vector<BYTE> ticket;
            struct TicketVectorWiper
            {
                std::vector<BYTE>& value;
                ~TicketVectorWiper() { thessley::ticket_broker::WipeTicket(&value); }
            } wipeTicket{ticket};
            hr = thessley::ticket_broker::ConsumeTicketForSid(_pszUserSid, &ticket);
            ProviderDiag(L"ConsumeAdLabTicket", hr,
                         SUCCEEDED(hr) ? static_cast<DWORD>(ticket.size()) : 0,
                         L"one-use local ticket broker; ticket bytes omitted");
            ULONG authPackage = 0;
            if (SUCCEEDED(hr)) hr = RetrieveKerberosAuthPackage(&authPackage);
            ProviderDiag(L"RetrieveAdTicketKerberosPackage", hr, authPackage);
            if (SUCCEEDED(hr))
            {
                LUID logonId{};
                const bool unlockScenario = _cpus == CPUS_UNLOCK_WORKSTATION;
                hr = BuildKerbTicketSerialization(
                    ticket.data(), ticket.size(), nullptr, 0,
                    unlockScenario, &logonId, authPackage,
                    CLSID_ThessleyAD, pcpcs, true);
                wchar_t layoutDetail[256]{};
                if (SUCCEEDED(hr) && pcpcs->rgbSerialization &&
                    pcpcs->cbSerialization >= sizeof(KERB_TICKET_LOGON))
                {
                    const auto* ticketLogon =
                        reinterpret_cast<const KERB_TICKET_LOGON*>(
                            pcpcs->rgbSerialization);
                    swprintf_s(layoutDetail, ARRAYSIZE(layoutDetail),
                        L"scenario=%s pointer_mode=native message_type=%lu flags=0x%08lX service_len=%lu service_pointer_field=0x%llX tgt_len=%lu tgt_pointer_field=0x%llX ticket_bytes_omitted",
                        unlockScenario ? L"unlock" : L"logon",
                        static_cast<unsigned long>(ticketLogon->MessageType),
                        static_cast<unsigned long>(ticketLogon->Flags),
                        static_cast<unsigned long>(ticketLogon->ServiceTicketLength),
                        static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(ticketLogon->ServiceTicket)),
                        static_cast<unsigned long>(ticketLogon->TicketGrantingTicketLength),
                        static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(ticketLogon->TicketGrantingTicket)));
                }
                ProviderDiag(L"BuildADTicketLogon", hr,
                    SUCCEEDED(hr) ? pcpcs->cbSerialization : 0,
                    layoutDetail[0] ? layoutDetail : L"serialization build failed");
            }
            if (SUCCEEDED(hr))
            {
                ProviderDiagTicketStatus(L"ADTicketSerializationReady",
                    STATUS_SUCCESS, STATUS_SUCCESS,
                    static_cast<DWORD>(_cpus), authPackage,
                    pcpcs->cbSerialization);
                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                return S_OK;
            }
            FreeKerbTicketSerialization(pcpcs);
            ProviderDiag(L"ADTicketLogonFailed", hr, 0,
                         L"ticket acquisition/serialization failed; no password fallback");
            wchar_t ticketError[256]{};
            swprintf_s(ticketError, ARRAYSIZE(ticketError),
                L"Windows ticket preparation failed (0x%08lX). Choose another sign-in option while this test is investigated.",
                static_cast<unsigned long>(hr));
            SHStrDupW(ticketError, ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_OK;
        }
        if (IsAdPasswordPlusPhoneTestMode(_adLabVscConfig))
        {
            PCWSTR enteredPassword = _rgFieldStrings[SFI_PASSWORD];
            if (!enteredPassword || !enteredPassword[0])
            {
                SHStrDupW(L"Phone approved. Enter the Windows password to continue.",
                          ppwszOptionalStatusText);
                *pcpsiOptionalStatusIcon = CPSI_WARNING;
                return S_OK;
            }

            // The phone approval is a one-use second factor. Hand the typed
            // password to Windows' normal Negotiate/interactive logon path;
            // never save it in a vault or log it.
            _phoneApproved.store(false);
            _phoneApprovedAt.store(0);
            PWSTR protectedPassword = nullptr;
            PWSTR domain = nullptr;
            PWSTR user = nullptr;
            KERB_INTERACTIVE_UNLOCK_LOGON interactive{};
            hr = ProtectIfNecessaryAndCopyPassword(
                const_cast<PWSTR>(enteredPassword), _cpus, &protectedPassword);
            ProviderDiag(L"ProtectAdPasswordPlusPhone", hr, 0);
            if (SUCCEEDED(hr))
            {
                hr = SplitDomainAndUsername(_pszQualifiedUserName, &domain, &user);
                ProviderDiag(L"SplitAdQualifiedName", hr, 0);
            }
            if (SUCCEEDED(hr))
                hr = KerbInteractiveUnlockLogonInit(domain, user, protectedPassword,
                                                     _cpus, &interactive);
            if (SUCCEEDED(hr))
                hr = KerbInteractiveUnlockLogonPack(interactive,
                    &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
            ULONG authPackage = 0;
            if (SUCCEEDED(hr)) hr = RetrieveNegotiateAuthPackage(&authPackage);

            if (protectedPassword)
            {
                SecureZeroMemory(protectedPassword,
                                 wcslen(protectedPassword) * sizeof(WCHAR));
                CoTaskMemFree(protectedPassword);
            }
            if (domain) CoTaskMemFree(domain);
            if (user) CoTaskMemFree(user);
            if (_rgFieldStrings[SFI_PASSWORD])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD],
                    wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
                _rgFieldStrings[SFI_PASSWORD] = nullptr;
                SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
                if (_pCredProvCredentialEvents)
                    _pCredProvCredentialEvents->SetFieldString(
                        this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
            }

            if (SUCCEEDED(hr))
            {
                pcpcs->ulAuthenticationPackage = authPackage;
                pcpcs->clsidCredentialProvider = CLSID_ThessleyAD;
                ProviderDiag(L"ADPasswordPlusPhoneReady", S_OK,
                             pcpcs->cbSerialization,
                             L"phone gate passed; normal Windows password serialization; password omitted");
                *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                return S_OK;
            }

            if (pcpcs->rgbSerialization)
            {
                SecureZeroMemory(pcpcs->rgbSerialization, pcpcs->cbSerialization);
                CoTaskMemFree(pcpcs->rgbSerialization);
                pcpcs->rgbSerialization = nullptr;
                pcpcs->cbSerialization = 0;
            }
            ProviderDiag(L"ADPasswordPlusPhoneFailed", hr, 0,
                         L"password serialization failed; password omitted");
            SHStrDupW(L"Could not prepare the Windows password sign-in. Request a new phone approval and try again.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_OK;
        }
        ProviderDiag(L"ADGetSerializationStart", S_OK, _vaultAvailable ? 1 : 0,
                     L"vault-available; no identity or PIN recorded");
        std::vector<WCHAR> savedPin;
        PasswordVectorWiper wipeSavedPin{savedPin};
        PCWSTR pin = _rgFieldStrings[SFI_PASSWORD];
        const bool typedPin = pin && pin[0];
        if (!typedPin && _vaultAvailable)
        {
            const HRESULT loadHr = ThessleyPinVaultLoad(_pszUserSid, savedPin);
            ProviderDiag(L"LoadAdCardPinVault", loadHr, 0);
            if (SUCCEEDED(loadHr)) pin = savedPin.data();
        }
        if (!pin || !pin[0])
        {
            SHStrDupW(L"Enter the TPM card PIN and submit. This phone approval stays valid briefly.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_OK;
        }

        if (_fChecked && typedPin)
        {
            const size_t chars = wcslen(pin) + 1;
            _pinPendingSave.assign(pin, pin + chars);
        }
        else
        {
            ThessleySecureClear(_pinPendingSave);
        }

        _phoneApproved.store(false); // every phone approval is single-use
        _phoneApprovedAt.store(0);
        PWSTR protectedPin = nullptr;
        PWSTR domain = nullptr;
        PWSTR user = nullptr;
        hr = ProtectIfNecessaryAndCopyPassword(const_cast<PWSTR>(pin), _cpus, &protectedPin);
        ProviderDiag(L"ProtectAdCardPin", hr, 0);
        if (SUCCEEDED(hr))
        {
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &domain, &user);
            ProviderDiag(L"SplitAdQualifiedName", hr, 0);
        }
        ULONG authPackage = 0;
        if (SUCCEEDED(hr))
        {
            hr = RetrieveKerberosAuthPackage(&authPackage);
            ProviderDiag(L"RetrieveAdKerberosPackage", hr, authPackage);
        }
        if (SUCCEEDED(hr))
        {
            LUID logonId{};
            DWORD consoleSessionId = 0xffffffff;
            const bool explicitUnlock = _cpus == CPUS_UNLOCK_WORKSTATION;
            const HRESULT unlockContextHr = GetActiveConsoleLogonIdForSid(
                _pszUserSid, !explicitUnlock, &consoleSessionId, &logonId);
            const bool unlockScenario = explicitUnlock || SUCCEEDED(unlockContextHr);
            wchar_t unlockContext[256]{};
            StringCchPrintfW(unlockContext, ARRAYSIZE(unlockContext),
                L"session=%lu logon_luid=%08lx:%08lx console_user_match=%u",
                static_cast<unsigned long>(consoleSessionId),
                static_cast<unsigned long>(logonId.HighPart),
                static_cast<unsigned long>(logonId.LowPart),
                SUCCEEDED(unlockContextHr) ? 1u : 0u);
            ProviderDiag(L"ADUnlockContextCheck", unlockContextHr,
                         unlockScenario ? 1u : 0u, unlockContext);
            ProviderDiag(L"ADSerializationScenario", S_OK, _cpus,
                unlockScenario ? (explicitUnlock
                    ? L"CPUS_UNLOCK_WORKSTATION; certificate-unlock serialization"
                    : L"CPUS_LOGON for matching locked console; certificate-unlock serialization")
                               : (_cpus == CPUS_LOGON
                                    ? L"CPUS_LOGON; certificate-logon serialization"
                                    : L"certificate-logon serialization"));
            wchar_t metadata[1024]{};
            StringCchPrintfW(metadata, ARRAYSIZE(metadata),
                L"Configured per-account VSC metadata; keySpec=%lu",
                IsPivPhoneTestMode(_adLabVscConfig)
                    ? _adLabVscConfig.pivKeySpec : _adLabVscConfig.keySpec);
            ProviderDiag(IsPivPhoneTestMode(_adLabVscConfig) ? L"AdPivMetadata" : L"ADVscMetadata",
                         S_OK, IsPivPhoneTestMode(_adLabVscConfig)
                            ? _adLabVscConfig.pivKeySpec : _adLabVscConfig.keySpec, metadata);
            if (IsPivPhoneTestMode(_adLabVscConfig))
                ProviderDiag(L"AdPivContainer", S_OK,
                    static_cast<DWORD>(_adLabVscConfig.pivContainerName.size()),
                    _adLabVscConfig.pivContainerName.c_str());
            if (explicitUnlock && FAILED(unlockContextHr))
                hr = unlockContextHr;
            else
                hr = BuildKerbCertificateSerialization(
                domain, user, protectedPin,
                (IsPivPhoneTestMode(_adLabVscConfig) ? _adLabVscConfig.pivCardName : _adLabVscConfig.cardName).c_str(),
                (IsPivPhoneTestMode(_adLabVscConfig) ? _adLabVscConfig.pivReaderName : _adLabVscConfig.readerName).c_str(),
                (IsPivPhoneTestMode(_adLabVscConfig) ? _adLabVscConfig.pivContainerName : _adLabVscConfig.containerName).c_str(),
                (IsPivPhoneTestMode(_adLabVscConfig) ? _adLabVscConfig.pivProviderName : _adLabVscConfig.providerName).c_str(),
                IsPivPhoneTestMode(_adLabVscConfig)
                    ? _adLabVscConfig.pivKeySpec : _adLabVscConfig.keySpec,
                unlockScenario, unlockScenario ? &logonId : nullptr,
                authPackage, CLSID_ThessleyAD, pcpcs);
            ProviderDiag(L"BuildADCertificateLogon", hr,
                         SUCCEEDED(hr) ? pcpcs->cbSerialization : 0,
                         unlockScenario ? L"certificate-unlock message_type=15"
                                        : L"certificate-logon message_type=13");
        }
        if (protectedPin)
        {
            SecureZeroMemory(protectedPin, wcslen(protectedPin) * sizeof(WCHAR));
            CoTaskMemFree(protectedPin);
        }
        CoTaskMemFree(domain);
        CoTaskMemFree(user);
        if (_rgFieldStrings[SFI_PASSWORD])
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD],
                             wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
            CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
            _rgFieldStrings[SFI_PASSWORD] = nullptr;
            SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        }

        if (SUCCEEDED(hr))
        {
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
            return S_OK;
        }

        ThessleySecureClear(_pinPendingSave);
        FreeKerbCertificateSerialization(pcpcs);
        ProviderDiag(L"ADGetSerializationFailed", hr, 0,
                     L"local serialization failed before LSA sign-in");
        SHStrDupW(IsPivPhoneTestMode(_adLabVscConfig)
                    ? L"Could not prepare PIV sign-in. Enter the disposable test PIN and request fresh approval."
                    : L"Could not prepare TPM sign-in. Re-enter the card PIN and request fresh phone approval.",
                  ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_OK;
    }

    std::vector<WCHAR> vaultPassword;
    PasswordVectorWiper wipeVaultPassword{vaultPassword};
    PCWSTR password = nullptr;

    if (_vaultAvailable && !_passwordEntryMode)
    {
        _phoneApproved.store(false);
        _phoneApprovedAt.store(0);
        const HRESULT loadHr = ThessleyPasswordVaultLoad(_pszUserSid, vaultPassword);
        ProviderDiag(L"LoadLocalPasswordVault", loadHr, 0);
        if (FAILED(loadHr))
        {
            SHStrDupW(L"The saved Windows credential could not be opened. Use Update saved QR sign-in or another Windows sign-in option.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
            return S_OK;
        }
        password = vaultPassword.data();
    }
    else if (!_passwordEntryMode)
    {
        SHStrDupW(L"Set up QR-only sign-in once, or choose another Windows sign-in option.",
                  ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_OK;
    }
    else if (!_rgFieldStrings[SFI_PASSWORD] || !_rgFieldStrings[SFI_PASSWORD][0])
    {
        SHStrDupW(L"Enter the Windows password to complete this sign-in.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_WARNING;
        return S_OK;
    }
    else
    {
        password = _rgFieldStrings[SFI_PASSWORD];
    }

    _phoneApproved.store(false); // exactly one Windows authentication attempt per phone approval
    _phoneApprovedAt.store(0);
    _savePasswordAfterSuccess = _passwordEntryMode && _fChecked;
    ThessleySecureClear(_passwordPendingSave);

    // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
    if (_fIsLocalUser)
    {
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(const_cast<PWSTR>(password), _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain;
            PWSTR pszUsername;
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {
                    // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                    // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                    // as necessary.
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                    if (SUCCEEDED(hr))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_ThessleyAD;
                            // At this point the credential has created the serialized credential used for logon
                            // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                            // that we have all the information we need and it should attempt to submit the
                            // serialized credential.
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                }
                CoTaskMemFree(pszDomain);
                CoTaskMemFree(pszUsername);
            }
            SecureZeroMemory(pwzProtectedPassword, wcslen(pwzProtectedPassword) * sizeof(WCHAR));
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

        // First get the size of the authentication buffer to allocate
        if (!CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(password), nullptr, &pcpcs->cbSerialization) &&
            (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
        {
            pcpcs->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(pcpcs->cbSerialization));
            if (pcpcs->rgbSerialization != nullptr)
            {
                hr = S_OK;

                // Retrieve the authentication buffer
                if (CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(password), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_ThessleyAD;

                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    if (SUCCEEDED(hr))
                    {
                        hr = E_FAIL;
                    }
                }

                if (FAILED(hr))
                {
                    CoTaskMemFree(pcpcs->rgbSerialization);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }

    if (SUCCEEDED(hr) && *pcpgsr == CPGSR_RETURN_CREDENTIAL_FINISHED && _savePasswordAfterSuccess)
    {
        const size_t chars = wcslen(password) + 1;
        _passwordPendingSave.assign(password, password + chars);
    }
    else
    {
        _savePasswordAfterSuccess = false;
    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    // Do not clear the phone request here. Windows may call ReportResult
    // before the smart-card/Kerberos stack sends GENERAL AUTHENTICATE. The
    // reader consumes the request id when the first valid signature APDU
    // arrives; clearing it here leaves the logon without its PKINIT signature.
    // Keep the NTSTATUS and its substatus as separate, explicitly hex fields.
    // Do not log account secrets, PINs, ticket data, or QR payloads.
    if (_adLabUser && IsTicketLogonTestMode(_adLabVscConfig))
        ProviderDiagTicketStatus(L"ReportResult", ntsStatus, ntsSubstatus,
                                 static_cast<DWORD>(_cpus), 0, 0);
    else
        ProviderDiag(L"ReportResult", static_cast<HRESULT>(ntsStatus),
                     static_cast<DWORD>(ntsSubstatus));
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (_adLabUser && IsTicketLogonTestMode(_adLabVscConfig) && ntsStatus < 0)
    {
        _phoneApproved.store(false);
        _phoneApprovedAt.store(0);
        wchar_t message[256]{};
        swprintf_s(message, ARRAYSIZE(message),
            L"Phone approved, but Windows rejected the ticket (0x%08lX / 0x%08lX). Choose another sign-in option while this test is investigated.",
            static_cast<unsigned long>(ntsStatus), static_cast<unsigned long>(ntsSubstatus));
        SHStrDupW(message, ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_OK;
    }

    if (ntsStatus == STATUS_SUCCESS && !_passwordPendingSave.empty())
    {
        const HRESULT saveHr = ThessleyPasswordVaultSave(_pszUserSid, _passwordPendingSave.data());
        ProviderDiag(L"SaveLocalPasswordVault", saveHr, 0);
        if (SUCCEEDED(saveHr))
        {
            _vaultAvailable = true;
            _passwordEntryMode = false;
            if (_rgFieldStrings[SFI_QR_SETUP_LINK])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_QR_SETUP_LINK],
                    wcslen(_rgFieldStrings[SFI_QR_SETUP_LINK]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_QR_SETUP_LINK]);
                _rgFieldStrings[SFI_QR_SETUP_LINK] = nullptr;
                SHStrDupW(L"Update saved QR sign-in", &_rgFieldStrings[SFI_QR_SETUP_LINK]);
            }
        }
        else
        {
            SHStrDupW(L"Windows sign-in succeeded, but QR setup could not be saved. Select Update saved QR sign-in to retry.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        }
    }
    if (_adLabUser && ntsStatus == STATUS_SUCCESS && !_pinPendingSave.empty())
    {
        const HRESULT saveHr = ThessleyPinVaultSave(_pszUserSid, _pinPendingSave.data());
        ProviderDiag(L"SaveAdCardPinVault", saveHr, 0);
        if (SUCCEEDED(saveHr))
        {
            _vaultAvailable = true;
            _passwordEntryMode = false;
            _fChecked = false;
            if (_rgFieldStrings[SFI_EDIT_TEXT])
            {
                SecureZeroMemory(_rgFieldStrings[SFI_EDIT_TEXT], wcslen(_rgFieldStrings[SFI_EDIT_TEXT]) * sizeof(WCHAR));
                CoTaskMemFree(_rgFieldStrings[SFI_EDIT_TEXT]);
            }
            _rgFieldStrings[SFI_EDIT_TEXT] = nullptr;
            SHStrDupW(IsPivPhoneTestMode(_adLabVscConfig)
                ? L"Your phone signs each Windows PIV login. The AD key stays on your phone."
                : L"Phone approval unlocks this PC's TPM sign-in key.",
                &_rgFieldStrings[SFI_EDIT_TEXT]);
            if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_HIDDEN);
                _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX, CPFS_HIDDEN);
                _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT, _rgFieldStrings[SFI_EDIT_TEXT]);
            }
        }
        else
        {
            SHStrDupW(L"Sign-in worked, but the encrypted PIN could not be saved. The next sign-in will ask for it once again.",
                      ppwszOptionalStatusText);
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        }
    }
    ThessleySecureClear(_pinPendingSave);
    ThessleySecureClear(_passwordPendingSave);
    _savePasswordAfterSuccess = false;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if (!*ppwszOptionalStatusText && (DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    if (ntsStatus == STATUS_LOGON_FAILURE && _vaultAvailable && !_passwordEntryMode)
    {
        _passwordEntryMode = true;
        _fChecked = TRUE;
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->BeginFieldUpdates();
            _pCredProvCredentialEvents->SetFieldState(this, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredProvCredentialEvents->SetFieldState(this, SFI_CHECKBOX, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredProvCredentialEvents->SetFieldCheckbox(this, SFI_CHECKBOX, TRUE,
                _adLabUser ? L"Remember TPM card PIN on this PC for QR-only sign-in (encrypted)"
                           : L"Save encrypted password for QR-only sign-in");
            _pCredProvCredentialEvents->SetFieldString(this, SFI_EDIT_TEXT,
                _adLabUser
                    ? L"The saved card PIN was rejected. Enter the current TPM PIN and approve the fresh QR to update it."
                    : L"The saved password was rejected. Enter the current Windows password to update QR-only sign-in.");
            _pCredProvCredentialEvents->SetFieldString(this, SFI_QR_SETUP_LINK,
                _adLabUser ? L"Cancel PIN update" : L"Cancel password update");
            _pCredProvCredentialEvents->EndFieldUpdates();
        }
    }

    // If we failed the logon, erase any typed password promptly.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
        if (_rgFieldStrings[SFI_PASSWORD])
        {
            SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], wcslen(_rgFieldStrings[SFI_PASSWORD]) * sizeof(WCHAR));
            CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
            _rgFieldStrings[SFI_PASSWORD] = nullptr;
            SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        }
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGONSTATUS_TEXT,
                !_fIsLocalUser
                    ? L"Smart-card sign-in failed. Check the TPM card PIN and request fresh phone approval."
                    : (_passwordEntryMode
                        ? L"Password was not accepted. Check it and submit again, or choose PIN."
                        : L"Sign-in failed. Request fresh phone approval, or choose PIN."));
        }
        if (_adLabUser) _StartApproval();
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    else if (_fOtherUserTile)
    {
        hr = S_FALSE;
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
