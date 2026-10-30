#pragma once

#include <windows.h>

#include <cstdint>
#include <vector>

namespace thessley::ticket_broker {

constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\ThessleyADTicketBrokerV1";
constexpr std::uint32_t kMagic = 0x54484B54; // THKT
constexpr std::uint32_t kVersion = 1;
constexpr DWORD kMaxSidBytes = 512;
constexpr DWORD kMaxTicketBytes = 1024 * 1024;

#pragma pack(push, 1)
struct RequestHeader {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t sidBytes;
};

struct ResponseHeader {
    std::uint32_t magic;
    std::uint32_t version;
    std::uint32_t status;
    std::uint32_t ticketBytes;
};
#pragma pack(pop)

// Returns a one-use, short-lived PAC-bearing HOST/<computer> service ticket
// bound by the broker to this exact Windows SID. The caller must wipe it.
HRESULT ConsumeTicketForSid(const wchar_t* sid, std::vector<BYTE>* ticket);
void WipeTicket(std::vector<BYTE>* ticket);

} // namespace thessley::ticket_broker
