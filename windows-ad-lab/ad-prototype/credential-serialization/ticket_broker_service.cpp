// Isolated Clone 1 feasibility broker. It captures one HOST service ticket
// from an interactive logon session into volatile memory, binds it to that
// session SID, and releases it once to LogonUI after a phone approval. It is
// not a production authentication service and must never be installed on a
// physical machine.

#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <wtsapi32.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ad_ticket_broker_protocol.h"

namespace {

constexpr wchar_t kServiceName[] = L"ThessleyADTicketBrokerTest";
constexpr auto kBrokerLifetime = std::chrono::minutes(3);
constexpr DWORD kMaxRequestBytes = 1024;

struct TicketEntry {
    std::vector<BYTE> bytes;
    std::chrono::steady_clock::time_point expires;
};

std::atomic<bool> g_stop{false};
std::mutex g_mutex;
std::map<std::wstring, TicketEntry> g_tickets;
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE g_pipeThread = nullptr;
std::mutex g_captureMutex;
std::vector<std::thread> g_captureThreads;
void CaptureSession(DWORD sessionId);

void StartCapture(DWORD sessionId) {
    std::lock_guard<std::mutex> lock(g_captureMutex);
    if (!g_stop.load()) g_captureThreads.emplace_back(CaptureSession, sessionId);
}

void Wipe(std::vector<BYTE>* bytes) {
    if (!bytes || bytes->empty()) return;
    SecureZeroMemory(bytes->data(), bytes->size());
    bytes->clear();
}

bool ReadExact(HANDLE pipe, void* data, DWORD bytes) {
    auto* cursor = static_cast<BYTE*>(data);
    DWORD offset = 0;
    while (offset < bytes) {
        DWORD received = 0;
        if (!ReadFile(pipe, cursor + offset, bytes - offset, &received, nullptr) ||
            received == 0) return false;
        offset += received;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* data, DWORD bytes) {
    const auto* cursor = static_cast<const BYTE*>(data);
    DWORD offset = 0;
    while (offset < bytes) {
        DWORD written = 0;
        if (!WriteFile(pipe, cursor + offset, bytes - offset, &written, nullptr) ||
            written == 0) return false;
        offset += written;
    }
    return true;
}

bool IsSidText(const wchar_t* sid, size_t chars) {
    if (!sid || chars < 5 || chars > 184 || sid[0] != L'S' || sid[1] != L'-')
        return false;
    for (size_t i = 0; i < chars; ++i) {
        if (sid[i] != L'-' && (sid[i] < L'0' || sid[i] > L'9')) return false;
    }
    return true;
}

bool IsEnabledTestSid(const std::wstring& sid) {
    const std::wstring path =
        L"SOFTWARE\\Thessley\\ADCredentialProvider\\Users\\" + sid;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0,
                      KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        return false;
    DWORD enabled = 0;
    DWORD bytes = sizeof(enabled);
    const LSTATUS status = RegGetValueW(key, nullptr, L"TicketLogonTest",
        RRF_RT_REG_DWORD, nullptr, &enabled, &bytes);
    RegCloseKey(key);
    return status == ERROR_SUCCESS && bytes == sizeof(enabled) && enabled == 1;
}

bool IsLogonUiClient(HANDLE pipe) {
    ULONG processId = 0;
    if (!GetNamedPipeClientProcessId(pipe, &processId) || processId == 0)
        return false;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) return false;
    wchar_t path[32768]{};
    DWORD length = ARRAYSIZE(path);
    const BOOL ok = QueryFullProcessImageNameW(process, 0, path, &length);
    CloseHandle(process);
    if (!ok || length == 0) return false;
    const wchar_t* name = wcsrchr(path, L'\\');
    name = name ? name + 1 : path;
    return _wcsicmp(name, L"LogonUI.exe") == 0;
}

bool RetrieveHostTicket(const LUID& logonId, std::vector<BYTE>* encodedTicket,
                        ULONGLONG* lifetime100ns) {
    if (!encodedTicket || !lifetime100ns) return false;
    encodedTicket->clear();
    *lifetime100ns = 0;

    wchar_t computer[256]{};
    DWORD chars = ARRAYSIZE(computer);
    if (!GetComputerNameExW(ComputerNameDnsFullyQualified, computer, &chars) ||
        chars == 0 || chars >= ARRAYSIZE(computer)) return false;
    std::wstring target = L"HOST/";
    target.append(computer, chars);
    if (target.size() > USHRT_MAX / sizeof(wchar_t)) return false;

    LSA_STRING processName{};
    constexpr char kProcess[] = "ThessleyTicketBrokerTest";
    processName.Buffer = const_cast<PCHAR>(kProcess);
    processName.Length = static_cast<USHORT>(sizeof(kProcess) - 1);
    processName.MaximumLength = static_cast<USHORT>(sizeof(kProcess));
    HANDLE lsa = nullptr;
    ULONG securityMode = 0;
    NTSTATUS status = LsaRegisterLogonProcess(&processName, &lsa, &securityMode);
    if (status < 0) return false;

    LSA_STRING kerberosName{};
    kerberosName.Buffer = const_cast<PCHAR>(MICROSOFT_KERBEROS_NAME_A);
    kerberosName.Length = static_cast<USHORT>(strlen(MICROSOFT_KERBEROS_NAME_A));
    kerberosName.MaximumLength = static_cast<USHORT>(kerberosName.Length + 1);
    ULONG packageId = 0;
    status = LsaLookupAuthenticationPackage(lsa, &kerberosName, &packageId);
    if (status < 0) {
        LsaDeregisterLogonProcess(lsa);
        return false;
    }

    const size_t targetBytes = target.size() * sizeof(wchar_t);
    std::vector<BYTE> requestBytes(sizeof(KERB_RETRIEVE_TKT_REQUEST) + targetBytes, 0);
    auto* request = reinterpret_cast<PKERB_RETRIEVE_TKT_REQUEST>(requestBytes.data());
    request->MessageType = KerbRetrieveEncodedTicketMessage;
    request->LogonId = logonId;
    request->TargetName.Length = static_cast<USHORT>(targetBytes);
    request->TargetName.MaximumLength = static_cast<USHORT>(targetBytes);
    request->TargetName.Buffer = reinterpret_cast<PWSTR>(
        requestBytes.data() + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    request->CacheOptions = 0; // cache hit or request a fresh ticket with the user's TGT
    memcpy(request->TargetName.Buffer, target.data(), targetBytes);

    PVOID response = nullptr;
    ULONG responseBytes = 0;
    NTSTATUS protocolStatus = 0;
    status = LsaCallAuthenticationPackage(lsa, packageId, request,
        static_cast<ULONG>(requestBytes.size()), &response, &responseBytes,
        &protocolStatus);
    SecureZeroMemory(requestBytes.data(), requestBytes.size());
    LsaDeregisterLogonProcess(lsa);
    if (status < 0 || protocolStatus < 0 || !response) {
        if (response) LsaFreeReturnBuffer(response);
        return false;
    }

    const auto* ticketResponse = static_cast<const KERB_RETRIEVE_TKT_RESPONSE*>(response);
    const auto& ticket = ticketResponse->Ticket;
    FILETIME nowFileTime{};
    GetSystemTimeAsFileTime(&nowFileTime);
    ULARGE_INTEGER now{};
    now.LowPart = nowFileTime.dwLowDateTime;
    now.HighPart = nowFileTime.dwHighDateTime;
    const ULONGLONG end = static_cast<ULONGLONG>(ticket.EndTime.QuadPart);
    const bool valid = ticket.EncodedTicket && ticket.EncodedTicketSize > 0 &&
        ticket.EncodedTicketSize <= thessley::ticket_broker::kMaxTicketBytes &&
        end > now.QuadPart;
    if (valid) {
        encodedTicket->assign(ticket.EncodedTicket,
                              ticket.EncodedTicket + ticket.EncodedTicketSize);
        *lifetime100ns = end - now.QuadPart;
    }
    LsaFreeReturnBuffer(response);
    return valid;
}

void CaptureSession(DWORD sessionId) {
    HANDLE token = nullptr;
    for (int attempt = 0; attempt < 20 && !g_stop.load(); ++attempt) {
        if (WTSQueryUserToken(sessionId, &token)) break;
        Sleep(250);
    }
    if (!token) return;
    TOKEN_STATISTICS statistics{};
    DWORD returned = 0;
    DWORD tokenBytes = 0;
    GetTokenInformation(token, TokenStatistics, nullptr, 0, &tokenBytes);
    std::vector<BYTE> tokenData(tokenBytes);
    const bool gotStats = tokenBytes >= sizeof(statistics) &&
        GetTokenInformation(token, TokenStatistics, tokenData.data(), tokenBytes, &returned);
    if (gotStats) statistics = *reinterpret_cast<const TOKEN_STATISTICS*>(tokenData.data());

    DWORD userBytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &userBytes);
    std::vector<BYTE> userData(userBytes);
    const bool gotUser = userBytes > sizeof(TOKEN_USER) &&
        GetTokenInformation(token, TokenUser, userData.data(), userBytes, &returned);
    CloseHandle(token);
    if (!gotStats || !gotUser) return;

    auto* tokenUser = reinterpret_cast<TOKEN_USER*>(userData.data());
    LPWSTR sid = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &sid)) return;
    std::wstring sidText(sid);
    LocalFree(sid);
    // Do not copy tickets from ordinary or administrator sessions. The
    // experimental account must be explicitly enabled by SID first.
    if (!IsEnabledTestSid(sidText)) return;

    // The session may need a brief moment after logon before its TGT exists.
    for (int attempt = 0; attempt < 20 && !g_stop.load(); ++attempt) {
        std::vector<BYTE> ticket;
        ULONGLONG ticketLifetime100ns = 0;
        if (RetrieveHostTicket(statistics.AuthenticationId, &ticket,
                               &ticketLifetime100ns)) {
            const auto ticketLifetime = std::chrono::duration_cast<
                std::chrono::steady_clock::duration>(std::chrono::nanoseconds(
                    ticketLifetime100ns * 100));
            const auto brokerLifetime = std::chrono::duration_cast<
                std::chrono::steady_clock::duration>(kBrokerLifetime);
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_stop.load()) {
                Wipe(&ticket);
                return;
            }
            auto old = g_tickets.find(sidText);
            if (old != g_tickets.end()) Wipe(&old->second.bytes);
            g_tickets[sidText] = TicketEntry{
                std::move(ticket), now + std::min(ticketLifetime, brokerLifetime)};
            return;
        }
        Sleep(500);
    }
}

void ReplyToClient(HANDLE pipe) {
    thessley::ticket_broker::RequestHeader request{};
    thessley::ticket_broker::ResponseHeader response{
        thessley::ticket_broker::kMagic,
        thessley::ticket_broker::kVersion,
        ERROR_INVALID_DATA,
        0};
    std::vector<BYTE> sidBytes;
    std::vector<BYTE> ticket;

    if (IsLogonUiClient(pipe) && ReadExact(pipe, &request, sizeof(request)) &&
        request.magic == thessley::ticket_broker::kMagic &&
        request.version == thessley::ticket_broker::kVersion &&
        request.sidBytes >= 12 && request.sidBytes <= thessley::ticket_broker::kMaxSidBytes &&
        request.sidBytes % sizeof(wchar_t) == 0) {
        sidBytes.resize(request.sidBytes + sizeof(wchar_t), 0);
        if (ReadExact(pipe, sidBytes.data(), request.sidBytes)) {
            const auto* sid = reinterpret_cast<const wchar_t*>(sidBytes.data());
            const size_t chars = request.sidBytes / sizeof(wchar_t);
            if (sid[chars - 1] == L'\0' && IsSidText(sid, chars - 1)) {
                std::lock_guard<std::mutex> lock(g_mutex);
                const auto found = g_tickets.find(sid);
                if (found != g_tickets.end()) {
                    if (found->second.expires > std::chrono::steady_clock::now()) {
                        ticket = std::move(found->second.bytes);
                        response.status = ERROR_SUCCESS;
                        response.ticketBytes = static_cast<DWORD>(ticket.size());
                    } else {
                        response.status = ERROR_TIMEOUT;
                        Wipe(&found->second.bytes);
                    }
                    g_tickets.erase(found); // one attempt; never replay
                } else {
                    response.status = ERROR_NOT_FOUND;
                }
            }
        }
    } else {
        response.status = ERROR_ACCESS_DENIED;
    }

    WriteExact(pipe, &response, sizeof(response));
    if (response.status == ERROR_SUCCESS && !ticket.empty())
        WriteExact(pipe, ticket.data(), response.ticketBytes);
    Wipe(&ticket);
    if (!sidBytes.empty()) SecureZeroMemory(sidBytes.data(), sidBytes.size());
}

DWORD WINAPI PipeLoop(LPVOID) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
        return GetLastError();
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
    while (!g_stop.load()) {
        HANDLE pipe = CreateNamedPipeW(
            thessley::ticket_broker::kPipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, thessley::ticket_broker::kMaxTicketBytes + 64,
            kMaxRequestBytes, 3000, &attributes);
        if (pipe == INVALID_HANDLE_VALUE) break;
        const BOOL connected = ConnectNamedPipe(pipe, nullptr)
            ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected && !g_stop.load()) ReplyToClient(pipe);
        FlushFileBuffers(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    LocalFree(descriptor);
    return 0;
}

DWORD WINAPI ServiceControl(DWORD control, DWORD eventType, LPVOID eventData, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        g_stop.store(true);
        if (g_statusHandle) {
            SERVICE_STATUS status{};
            status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
            status.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_statusHandle, &status);
        }
        // Wake the blocking pipe accept so the worker can exit cleanly.
        HANDLE wake = CreateFileW(thessley::ticket_broker::kPipeName,
            GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (wake != INVALID_HANDLE_VALUE) CloseHandle(wake);
    } else if (control == SERVICE_CONTROL_SESSIONCHANGE &&
               eventType == WTS_SESSION_LOGON && eventData && !g_stop.load()) {
        const auto* notification = static_cast<const WTSSESSION_NOTIFICATION*>(eventData);
        const DWORD sessionId = notification->dwSessionId;
        StartCapture(sessionId);
    }
    return NO_ERROR;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_statusHandle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControl, nullptr);
    if (!g_statusHandle) return;
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_statusHandle, &status);

    // Establish the protected local pipe before advertising the service ready.
    g_pipeThread = CreateThread(nullptr, 0, PipeLoop, nullptr, 0, nullptr);
    if (!g_pipeThread) {
        status.dwCurrentState = SERVICE_STOPPED;
        status.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_statusHandle, &status);
        return;
    }
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN |
        SERVICE_ACCEPT_SESSIONCHANGE;
    status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_statusHandle, &status);

    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            if (sessions[i].State == WTSActive)
                StartCapture(sessions[i].SessionId);
        }
        WTSFreeMemory(sessions);
    }

    WaitForSingleObject(g_pipeThread, INFINITE);
    CloseHandle(g_pipeThread);
    g_pipeThread = nullptr;
    std::vector<std::thread> captureThreads;
    {
        std::lock_guard<std::mutex> lock(g_captureMutex);
        captureThreads.swap(g_captureThreads);
    }
    for (auto& thread : captureThreads)
        if (thread.joinable()) thread.join();
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (auto& entry : g_tickets) Wipe(&entry.second.bytes);
        g_tickets.clear();
    }
    status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_statusHandle, &status);
}

} // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr}
    };
    return StartServiceCtrlDispatcherW(table) ? 0 : static_cast<int>(GetLastError());
}
