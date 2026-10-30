// Disposable lab probe for the Windows Kerberos ticket-logon path.
// Retrieves a cached host ticket from a specified logon session by running as
// LocalSystem, submits it to LSA with no TGT, and reports only status/token
// metadata. It never writes ticket bytes or account secrets to disk or output.

#include <windows.h>
#include <ntsecapi.h>

#include <cstdio>
#include <cwchar>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace {

void PrintStatus(const char* label, NTSTATUS status) {
    std::printf("%s=0x%08lx\n", label,
                static_cast<unsigned long>(status));
}

bool RetrieveCachedTicket(HANDLE lsa, ULONG packageId, const LUID& logonId,
                          const std::wstring& target,
                          std::vector<BYTE>* encodedTicket) {
    if (!encodedTicket || target.empty() ||
        target.size() > (std::numeric_limits<USHORT>::max() / sizeof(WCHAR)))
        return false;

    const size_t stringBytes = target.size() * sizeof(WCHAR);
    std::vector<BYTE> requestBytes(sizeof(KERB_RETRIEVE_TKT_REQUEST) +
                                   stringBytes, 0);
    auto* request = reinterpret_cast<PKERB_RETRIEVE_TKT_REQUEST>(
        requestBytes.data());
    request->MessageType = KerbRetrieveEncodedTicketMessage;
    request->LogonId = logonId;
    request->TargetName.Length = static_cast<USHORT>(stringBytes);
    request->TargetName.MaximumLength = static_cast<USHORT>(stringBytes);
    request->TargetName.Buffer = reinterpret_cast<PWSTR>(
        requestBytes.data() + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    request->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
    std::memcpy(request->TargetName.Buffer, target.data(), stringBytes);

    PVOID response = nullptr;
    ULONG responseBytes = 0;
    NTSTATUS protocolStatus = 0;
    const NTSTATUS callStatus = LsaCallAuthenticationPackage(
        lsa, packageId, request, static_cast<ULONG>(requestBytes.size()),
        &response, &responseBytes, &protocolStatus);
    requestBytes.clear();

    if (callStatus < 0 || protocolStatus < 0 || response == nullptr) {
        PrintStatus("ticket_api_status", callStatus);
        PrintStatus("ticket_protocol_status", protocolStatus);
        if (response) LsaFreeReturnBuffer(response);
        return false;
    }

    const auto* ticketResponse =
        static_cast<const KERB_RETRIEVE_TKT_RESPONSE*>(response);
    const auto& ticket = ticketResponse->Ticket;
    if (ticket.EncodedTicket == nullptr || ticket.EncodedTicketSize == 0 ||
        ticket.EncodedTicketSize > 1024 * 1024) {
        std::puts("ticket_result=invalid-or-too-large");
        LsaFreeReturnBuffer(response);
        return false;
    }

    encodedTicket->assign(ticket.EncodedTicket,
                          ticket.EncodedTicket + ticket.EncodedTicketSize);
    LsaFreeReturnBuffer(response);
    return true;
}

void Wipe(std::vector<BYTE>* bytes) {
    if (!bytes || bytes->empty()) return;
    SecureZeroMemory(bytes->data(), bytes->size());
    bytes->clear();
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 4) {
        std::fputs("usage: ticket_logon_probe.exe <luid-low-hex> <host-spn> <interactive|network>\n",
                   stderr);
        return 2;
    }

    wchar_t* end = nullptr;
    const unsigned long lowPart = std::wcstoul(argv[1], &end, 16);
    if (end == argv[1] || *end != L'\0') return 2;
    LUID logonId{};
    logonId.LowPart = static_cast<DWORD>(lowPart);
    SECURITY_LOGON_TYPE logonType = Interactive;
    if (std::wcscmp(argv[3], L"network") == 0) {
        logonType = Network;
    } else if (std::wcscmp(argv[3], L"interactive") != 0) {
        std::fputs("logon type must be interactive or network\n", stderr);
        return 2;
    }

    LSA_STRING processName{};
    constexpr char kProcessName[] = "ThessleyTicketProbe";
    processName.Buffer = const_cast<PCHAR>(kProcessName);
    processName.Length = static_cast<USHORT>(sizeof(kProcessName) - 1);
    processName.MaximumLength = static_cast<USHORT>(sizeof(kProcessName));

    HANDLE lsa = nullptr;
    ULONG securityMode = 0;
    NTSTATUS status = LsaRegisterLogonProcess(&processName, &lsa,
                                               &securityMode);
    if (status < 0) {
        PrintStatus("register_logon_process", status);
        return 3;
    }

    LSA_STRING kerberosName{};
    kerberosName.Buffer = const_cast<PCHAR>(MICROSOFT_KERBEROS_NAME_A);
    kerberosName.Length = static_cast<USHORT>(
        std::strlen(MICROSOFT_KERBEROS_NAME_A));
    kerberosName.MaximumLength = static_cast<USHORT>(kerberosName.Length + 1);
    ULONG packageId = 0;
    status = LsaLookupAuthenticationPackage(lsa, &kerberosName, &packageId);
    if (status < 0) {
        PrintStatus("lookup_kerberos_package", status);
        LsaDeregisterLogonProcess(lsa);
        return 4;
    }

    const std::wstring hostSpn(argv[2]);
    std::vector<BYTE> serviceTicket;
    if (!RetrieveCachedTicket(lsa, packageId, logonId, hostSpn,
                              &serviceTicket)) {
        Wipe(&serviceTicket);
        LsaDeregisterLogonProcess(lsa);
        return 5;
    }

    TOKEN_SOURCE source{};
    std::memcpy(source.SourceName, "TSHLYTKT", sizeof(source.SourceName));
    if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
        std::printf("allocate_token_source=0x%08lx\n",
                    static_cast<unsigned long>(GetLastError()));
        Wipe(&serviceTicket);
        LsaDeregisterLogonProcess(lsa);
        return 7;
    }

    LSA_STRING originName{};
    constexpr char kOrigin[] = "ThessleyTicketProbe";
    originName.Buffer = const_cast<PCHAR>(kOrigin);
    originName.Length = static_cast<USHORT>(sizeof(kOrigin) - 1);
    originName.MaximumLength = static_cast<USHORT>(sizeof(kOrigin));

    PVOID profile = nullptr;
    ULONG profileBytes = 0;
    LUID newLogonId{};
    HANDLE token = nullptr;
    QUOTA_LIMITS quotas{};
    NTSTATUS subStatus = 0;

    // LsaLogonUser requires its input buffers to be contiguous. This native
    // LSA probe uses an in-buffer pointer; the separate Credential Provider
    // serializer represents the same buffer members as offsets.
    if (serviceTicket.size() >
        std::numeric_limits<ULONG>::max() - sizeof(KERB_TICKET_LOGON)) {
        Wipe(&serviceTicket);
        LsaDeregisterLogonProcess(lsa);
        return 6;
    }
    std::vector<BYTE> input(sizeof(KERB_TICKET_LOGON) + serviceTicket.size(), 0);
    auto* logon = reinterpret_cast<PKERB_TICKET_LOGON>(input.data());
    logon->MessageType = KerbTicketLogon;
    logon->Flags = 0;
    logon->ServiceTicketLength = static_cast<ULONG>(serviceTicket.size());
    logon->TicketGrantingTicketLength = 0;
    logon->ServiceTicket = input.data() + sizeof(KERB_TICKET_LOGON);
    logon->TicketGrantingTicket = nullptr;
    std::memcpy(logon->ServiceTicket, serviceTicket.data(), serviceTicket.size());
    Wipe(&serviceTicket);

    status = LsaLogonUser(
        lsa, &originName, logonType,
        packageId, input.data(), static_cast<ULONG>(input.size()),
        nullptr, &source, &profile, &profileBytes, &newLogonId, &token,
        &quotas, &subStatus);
    Wipe(&input);
    PrintStatus("lsa_logon_user", status);
    PrintStatus("lsa_substatus", subStatus);
    std::printf("logon_type=%s\n",
                logonType == Interactive ? "interactive" : "network");
    if (profile && status >= 0) {
        const auto* ticketProfile = static_cast<const KERB_TICKET_PROFILE*>(profile);
        std::printf("profile_type=%lu\n",
                    static_cast<unsigned long>(
                        ticketProfile->Profile.MessageType));
        std::printf("new_logon_luid=%08lx:%08lx\n",
                    static_cast<unsigned long>(newLogonId.HighPart),
                    static_cast<unsigned long>(newLogonId.LowPart));
        TOKEN_TYPE tokenType{};
        DWORD returned = 0;
        if (token && GetTokenInformation(token, TokenType, &tokenType,
                                         sizeof(tokenType), &returned)) {
            std::printf("token_type=%s\n",
                        tokenType == TokenPrimary ? "primary" : "impersonation");
        }
    }
    if (token) CloseHandle(token);
    if (profile) LsaFreeReturnBuffer(profile);
    LsaDeregisterLogonProcess(lsa);
    return status < 0 ? 8 : 0;
}
