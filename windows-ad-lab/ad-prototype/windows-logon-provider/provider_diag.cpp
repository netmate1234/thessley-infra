#include "provider_diag.h"
#include <strsafe.h>
#include <mutex>

void ProviderDiag(const wchar_t *eventName, HRESULT result, DWORD count, const wchar_t *detail)
{
    static std::mutex lock;
    std::lock_guard<std::mutex> guard(lock);
 #ifdef THESSLEY_TICKET_LOGON_TEST
    constexpr wchar_t kProviderLog[] =
        L"C:\\ProgramData\\ThessleyPamWin\\ad-ticket-logon-test\\provider.log";
 #else
    constexpr wchar_t kProviderLog[] =
        L"C:\\ProgramData\\ThessleyPamWin\\ad-credential-provider\\provider.log";
 #endif
    HANDLE file = CreateFileW(
        kProviderLog,
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME now{};
    GetSystemTime(&now);
    wchar_t line[768]{};
    if (FAILED(StringCchPrintfW(line, ARRAYSIZE(line),
            L"%04u-%02u-%02uT%02u:%02u:%02uZ event=%s hr=0x%08lX count=%lu detail=%s\r\n",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
            eventName ? eventName : L"unknown", static_cast<unsigned long>(result), count,
            detail ? detail : L""))) {
        CloseHandle(file);
        return;
    }
    char utf8[512]{};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8,
        static_cast<int>(sizeof(utf8)), nullptr, nullptr);
    if (bytes > 1) {
        DWORD written = 0;
        WriteFile(file, utf8, static_cast<DWORD>(bytes - 1), &written, nullptr);
    }
    CloseHandle(file);
}

void ProviderDiagTicketStatus(const wchar_t *eventName, NTSTATUS status,
                              NTSTATUS substatus, DWORD usageScenario,
                              ULONG authenticationPackage,
                              DWORD serializedBytes)
{
    static std::mutex lock;
    std::lock_guard<std::mutex> guard(lock);
#ifdef THESSLEY_TICKET_LOGON_TEST
    constexpr wchar_t kProviderLog[] =
        L"C:\\ProgramData\\ThessleyPamWin\\ad-ticket-logon-test\\provider.log";
#else
    constexpr wchar_t kProviderLog[] =
        L"C:\\ProgramData\\ThessleyPamWin\\ad-credential-provider\\provider.log";
#endif
    HANDLE file = CreateFileW(kProviderLog, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return;

    SYSTEMTIME now{};
    GetSystemTime(&now);
    wchar_t line[512]{};
    if (FAILED(StringCchPrintfW(line, ARRAYSIZE(line),
            L"%04u-%02u-%02uT%02u:%02u:%02uZ event=%s status=0x%08lX substatus=0x%08lX scenario=%lu auth_package=%lu serialized_bytes=%lu\r\n",
            now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
            eventName ? eventName : L"TicketStatus",
            static_cast<unsigned long>(status),
            static_cast<unsigned long>(substatus),
            static_cast<unsigned long>(usageScenario),
            static_cast<unsigned long>(authenticationPackage),
            static_cast<unsigned long>(serializedBytes)))) {
        CloseHandle(file);
        return;
    }
    char utf8[768]{};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, line, -1, utf8,
        static_cast<int>(sizeof(utf8)), nullptr, nullptr);
    if (bytes > 1) {
        DWORD written = 0;
        WriteFile(file, utf8, static_cast<DWORD>(bytes - 1), &written, nullptr);
    }
    CloseHandle(file);
}
