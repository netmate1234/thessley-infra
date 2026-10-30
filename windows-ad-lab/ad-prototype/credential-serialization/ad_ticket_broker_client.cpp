#include "ad_ticket_broker_protocol.h"

#include <sddl.h>

#include <cstring>
#include <limits>
#include <string>

namespace thessley::ticket_broker {
namespace {

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

bool ValidSidText(const wchar_t* sid, size_t* chars) {
    if (!sid || !chars || sid[0] != L'S' || sid[1] != L'-') return false;
    size_t count = 0;
    for (const wchar_t* p = sid; *p; ++p) {
        if (*p != L'-' && (*p < L'0' || *p > L'9')) return false;
        if (++count > 184) return false;
    }
    *chars = count;
    return count >= 5;
}

} // namespace

HRESULT ConsumeTicketForSid(const wchar_t* sid, std::vector<BYTE>* ticket) {
    if (!ticket) return E_POINTER;
    WipeTicket(ticket);

    size_t sidChars = 0;
    if (!ValidSidText(sid, &sidChars) ||
        sidChars > (kMaxSidBytes / sizeof(wchar_t)) - 1) return E_INVALIDARG;

    const DWORD sidBytes = static_cast<DWORD>((sidChars + 1) * sizeof(wchar_t));
    if (!WaitNamedPipeW(kPipeName, 2000))
        return HRESULT_FROM_WIN32(GetLastError());
    HANDLE pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    HRESULT result = E_FAIL;
    RequestHeader request{kMagic, kVersion, sidBytes};
    ResponseHeader response{};
    try {
        if (!WriteExact(pipe, &request, sizeof(request)) ||
            !WriteExact(pipe, sid, sidBytes) ||
            !ReadExact(pipe, &response, sizeof(response))) {
            result = HRESULT_FROM_WIN32(GetLastError());
        } else if (response.magic != kMagic || response.version != kVersion ||
                   response.ticketBytes > kMaxTicketBytes) {
            result = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        } else if (response.status != ERROR_SUCCESS || response.ticketBytes == 0) {
            result = HRESULT_FROM_WIN32(response.status ? response.status : ERROR_NO_LOGON_SERVERS);
        } else {
            ticket->resize(response.ticketBytes);
            if (ReadExact(pipe, ticket->data(), response.ticketBytes)) {
                result = S_OK;
            } else {
                WipeTicket(ticket);
                result = HRESULT_FROM_WIN32(GetLastError());
            }
        }
    } catch (...) {
        WipeTicket(ticket);
        result = E_OUTOFMEMORY;
    }
    FlushFileBuffers(pipe);
    CloseHandle(pipe);
    return result;
}

void WipeTicket(std::vector<BYTE>* ticket) {
    if (!ticket || ticket->empty()) return;
    SecureZeroMemory(ticket->data(), ticket->size());
    ticket->clear();
}

} // namespace thessley::ticket_broker
