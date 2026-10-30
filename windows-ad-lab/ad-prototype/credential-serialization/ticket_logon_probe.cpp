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

#include "kerb_ticket_serialization.h"

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
    if (argc < 4 || argc > 6) {
        std::fputs("usage: ticket_logon_probe.exe <luid-low-hex> <host-spn> <interactive|network> [kerberos|negotiate] [native-pointers|raw-offsets|both-pointer-modes]\n",
                   stderr);
        return 2;
    }

    bool negotiatePackage = false;
    bool rawOffsets = false;
    bool bothPointerModes = false;
    bool packageChoiceSeen = false;
    bool pointerChoiceSeen = false;
    for (int i = 4; i < argc; ++i) {
        if (std::wcscmp(argv[i], L"kerberos") == 0 ||
            std::wcscmp(argv[i], L"negotiate") == 0) {
            if (packageChoiceSeen) {
                std::fputs("specify only one authentication package\n", stderr);
                return 2;
            }
            packageChoiceSeen = true;
            negotiatePackage = std::wcscmp(argv[i], L"negotiate") == 0;
        } else if (std::wcscmp(argv[i], L"native-pointers") == 0 ||
                   std::wcscmp(argv[i], L"raw-offsets") == 0 ||
                   std::wcscmp(argv[i], L"both-pointer-modes") == 0) {
            if (pointerChoiceSeen) {
                std::fputs("specify only one pointer mode\n", stderr);
                return 2;
            }
            pointerChoiceSeen = true;
            rawOffsets = std::wcscmp(argv[i], L"raw-offsets") == 0;
            bothPointerModes =
                std::wcscmp(argv[i], L"both-pointer-modes") == 0;
        } else {
            std::fputs("unknown optional argument\n", stderr);
            return 2;
        }
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

    if (negotiatePackage) {
        char name[] = "Negotiate";
        LSA_STRING negotiateName{};
        negotiateName.Buffer = name;
        negotiateName.Length = sizeof(name) - 1;
        negotiateName.MaximumLength = sizeof(name);
        status = LsaLookupAuthenticationPackage(lsa, &negotiateName, &packageId);
        if (status < 0) {
            PrintStatus("lookup_negotiate_package", status);
            Wipe(&serviceTicket);
            LsaDeregisterLogonProcess(lsa);
            return 4;
        }
    }
    std::printf("authentication_package_id=%lu\n", static_cast<unsigned long>(packageId));
    TOKEN_SOURCE source{};
    std::memcpy(source.SourceName, "TSHLYTKT", sizeof(source.SourceName));

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

    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
    const CLSID probeClsid = {0x6f0de0cc, 0x3645, 0x4f21,
                              {0x9d, 0x5c, 0x9f, 0x57, 0x38, 0x2f, 0x92, 0x1b}};
    const HRESULT buildHr = BuildKerbTicketSerialization(
        serviceTicket.data(), serviceTicket.size(), nullptr, 0, false, nullptr,
        packageId,
        probeClsid, &serialization);
    Wipe(&serviceTicket);
    if (FAILED(buildHr)) {
        std::printf("build_serialization=0x%08lx\n",
                    static_cast<unsigned long>(buildHr));
        LsaDeregisterLogonProcess(lsa);
        return 6;
    }

    // Compare native LSA pointers with the unchanged serialized offsets.
    // Success after fixup alone does not prove Winlogon performs that fixup.
    if (serialization.cbSerialization < sizeof(KERB_TICKET_LOGON)) {
        FreeKerbTicketSerialization(&serialization);
        LsaDeregisterLogonProcess(lsa);
        return 6;
    }
    auto* logon = reinterpret_cast<PKERB_TICKET_LOGON>(
        serialization.rgbSerialization);
    const ULONG_PTR serviceOffset =
        reinterpret_cast<ULONG_PTR>(logon->ServiceTicket);
    if (serviceOffset < sizeof(KERB_TICKET_LOGON) ||
        serviceOffset > serialization.cbSerialization ||
        logon->ServiceTicketLength >
            serialization.cbSerialization - serviceOffset ||
        logon->TicketGrantingTicketLength != 0) {
        FreeKerbTicketSerialization(&serialization);
        LsaDeregisterLogonProcess(lsa);
        return 6;
    }
    bool anyFailure = false;
    const int modeCount = bothPointerModes ? 2 : 1;
    for (int modeIndex = 0; modeIndex < modeCount; ++modeIndex) {
        const bool useRawOffsets = bothPointerModes
            ? modeIndex == 1 : rawOffsets;
        std::vector<BYTE> attemptBuffer(
            serialization.rgbSerialization,
            serialization.rgbSerialization + serialization.cbSerialization);
        auto* attemptLogon = reinterpret_cast<PKERB_TICKET_LOGON>(
            attemptBuffer.data());
        attemptLogon->ServiceTicket = useRawOffsets
            ? reinterpret_cast<PUCHAR>(serviceOffset)
            : attemptBuffer.data() + serviceOffset;
        attemptLogon->TicketGrantingTicket = nullptr;
        if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
            std::printf("allocate_token_source=0x%08lx\n",
                        static_cast<unsigned long>(GetLastError()));
            anyFailure = true;
            Wipe(&attemptBuffer);
            break;
        }
        profile = nullptr;
        profileBytes = 0;
        newLogonId = {};
        token = nullptr;
        subStatus = 0;
        status = LsaLogonUser(
            lsa, &originName, logonType,
            serialization.ulAuthenticationPackage,
            attemptBuffer.data(), static_cast<ULONG>(attemptBuffer.size()),
            nullptr, &source, &profile, &profileBytes, &newLogonId, &token,
            &quotas, &subStatus);
        std::printf("pointer_mode=%s\n",
                    useRawOffsets ? "raw-offsets" : "native-pointers");
        PrintStatus("lsa_logon_user", status);
        PrintStatus("lsa_substatus", subStatus);
        std::printf("logon_type=%s\n",
                    logonType == Interactive ? "interactive" : "network");
        if (profile && status >= 0) {
            const auto* ticketProfile =
                static_cast<const KERB_TICKET_PROFILE*>(profile);
            std::printf("profile_type=%lu\n",
                static_cast<unsigned long>(ticketProfile->Profile.MessageType));
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
        if (status < 0) anyFailure = true;
        if (token) CloseHandle(token);
        if (profile) LsaFreeReturnBuffer(profile);
        token = nullptr;
        profile = nullptr;
        Wipe(&attemptBuffer);
    }
    FreeKerbTicketSerialization(&serialization);
    LsaDeregisterLogonProcess(lsa);
    return anyFailure ? 8 : 0;
}
