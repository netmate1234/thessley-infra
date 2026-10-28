#include "ad_approval_client.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

namespace {

constexpr size_t kMaxOutput = 64 * 1024;
constexpr DWORD kPollIntervalMs = 50;

class ScopedHandle {
public:
    explicit ScopedHandle(HANDLE value = nullptr) : value_(value) {}
    ~ScopedHandle() { reset(); }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
    HANDLE get() const { return value_; }
    HANDLE release() { HANDLE value = value_; value_ = nullptr; return value; }
    void reset(HANDLE value = nullptr) {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_;
};

bool SafeToken(PCWSTR value, const wchar_t* allowed, bool allowDash) {
    if (value == nullptr || value[0] == L'\0') return false;
    for (const wchar_t* p = value; *p; ++p) {
        const bool alphaNumeric = (*p >= L'a' && *p <= L'z') ||
                                  (*p >= L'A' && *p <= L'Z') ||
                                  (*p >= L'0' && *p <= L'9');
        if (alphaNumeric || (allowDash && *p == L'-')) continue;
        bool found = false;
        for (const wchar_t* a = allowed; a && *a; ++a) found = found || *p == *a;
        if (!found) return false;
    }
    return true;
}

std::wstring QuoteArgument(const std::wstring& value) {
    std::wstring quoted = L"\"";
    size_t slashes = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') {
            ++slashes;
            continue;
        }
        if (ch == L'"') {
            quoted.append(slashes * 2 + 1, L'\\');
            quoted.push_back(ch);
        } else {
            quoted.append(slashes, L'\\');
            quoted.push_back(ch);
        }
        slashes = 0;
    }
    quoted.append(slashes * 2, L'\\');
    quoted.push_back(L'"');
    return quoted;
}

HRESULT RunAgent(const std::vector<std::wstring>& arguments,
                 const std::atomic_bool& cancelled, std::string* output) {
    if (output == nullptr) return E_POINTER;
    ClearAdApprovalOutput(output);

    const std::wstring python = L"C:\\Program Files\\Python313\\python.exe";
    const std::wstring entry = L"C:\\ProgramData\\ThessleyPamWin\\ad-prototype\\ad_main.py";
    std::wstring command = QuoteArgument(python) + L" -I -X utf8 " + QuoteArgument(entry);
    for (const auto& argument : arguments) command += L" " + QuoteArgument(argument);
    if (command.size() > 32760) return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
    std::vector<wchar_t> writable(command.begin(), command.end());
    writable.push_back(L'\0');

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE rawRead = nullptr, rawWrite = nullptr;
    if (!CreatePipe(&rawRead, &rawWrite, &security, 0))
        return HRESULT_FROM_WIN32(GetLastError());
    ScopedHandle readPipe(rawRead), writePipe(rawWrite);
    if (!SetHandleInformation(readPipe.get(), HANDLE_FLAG_INHERIT, 0))
        return HRESULT_FROM_WIN32(GetLastError());

    ScopedHandle stdinHandle(CreateFileW(L"NUL", GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (stdinHandle.get() == INVALID_HANDLE_VALUE)
        return HRESULT_FROM_WIN32(GetLastError());

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = stdinHandle.get();
    startup.hStdOutput = writePipe.get();
    startup.hStdError = writePipe.get();
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessW(python.c_str(), writable.data(), nullptr, nullptr,
        TRUE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr,
        &startup, &process);
    if (!created) return HRESULT_FROM_WIN32(GetLastError());
    ScopedHandle processHandle(process.hProcess), threadHandle(process.hThread);
    writePipe.reset(); // Parent must close its writer so EOF arrives after the child exits.

    std::array<char, 4096> chunk{};
    HRESULT result = S_OK;
    bool processEnded = false;
    while (!processEnded) {
        if (cancelled.load()) {
            TerminateProcess(processHandle.get(), ERROR_CANCELLED);
            WaitForSingleObject(processHandle.get(), 2000);
            result = HRESULT_FROM_WIN32(ERROR_CANCELLED);
            break;
        }

        DWORD available = 0;
        if (!PeekNamedPipe(readPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
            const DWORD error = GetLastError();
            if (error != ERROR_BROKEN_PIPE) result = HRESULT_FROM_WIN32(error);
            break;
        }
        while (available != 0) {
            const DWORD wanted = static_cast<DWORD>(std::min<size_t>(chunk.size(), available));
            DWORD received = 0;
            if (!ReadFile(readPipe.get(), chunk.data(), wanted, &received, nullptr)) {
                const DWORD error = GetLastError();
                if (error != ERROR_BROKEN_PIPE) result = HRESULT_FROM_WIN32(error);
                break;
            }
            if (received == 0) break;
            if (output->size() > kMaxOutput - received) {
                TerminateProcess(processHandle.get(), ERROR_BUFFER_OVERFLOW);
                WaitForSingleObject(processHandle.get(), 2000);
                result = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
                break;
            }
            output->append(chunk.data(), received);
            if (!PeekNamedPipe(readPipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
                if (GetLastError() != ERROR_BROKEN_PIPE) result = HRESULT_FROM_WIN32(GetLastError());
                available = 0;
            }
        }
        if (FAILED(result)) break;
        const DWORD wait = WaitForSingleObject(processHandle.get(), kPollIntervalMs);
        if (wait == WAIT_OBJECT_0) processEnded = true;
        else if (wait == WAIT_FAILED) {
            result = HRESULT_FROM_WIN32(GetLastError());
            break;
        }
    }

    if (SUCCEEDED(result)) {
        // Drain bytes written just before process exit.
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(readPipe.get(), nullptr, 0, nullptr, &available, nullptr) || available == 0) break;
            const DWORD wanted = static_cast<DWORD>(std::min<size_t>(chunk.size(), available));
            DWORD received = 0;
            if (!ReadFile(readPipe.get(), chunk.data(), wanted, &received, nullptr) || received == 0) break;
            if (output->size() > kMaxOutput - received) {
                result = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
                break;
            }
            output->append(chunk.data(), received);
        }
    }

    DWORD exitCode = ERROR_GEN_FAILURE;
    bool preserveCliDiagnostic = false;
    if (GetExitCodeProcess(processHandle.get(), &exitCode) && SUCCEEDED(result) && exitCode != 0) {
        result = HRESULT_FROM_WIN32(exitCode);
        preserveCliDiagnostic = true;
    }
    if (result == HRESULT_FROM_WIN32(ERROR_CANCELLED))
        ClearAdApprovalOutput(output);
    else if (FAILED(result) && !preserveCliDiagnostic)
        ClearAdApprovalOutput(output);
    return result;
}

} // namespace

HRESULT StartAdApprovalForSid(PCWSTR sid, PCWSTR context,
                              const std::atomic_bool& cancelled,
                              std::string* output) {
    if (!SafeToken(sid, L"-", false) || wcslen(sid) > 184 ||
        wcsncmp(sid, L"S-1-", 4) != 0)
        return E_INVALIDARG;
    if (context == nullptr ||
        (wcscmp(context, L"interactive") != 0 && wcscmp(context, L"unlock") != 0))
        return E_INVALIDARG;
    return RunAgent({L"approval-start", L"--sid", sid, L"--context", context}, cancelled, output);
}

HRESULT PollAdApproval(PCWSTR requestId, DWORD timeoutSeconds,
                       const std::atomic_bool& cancelled,
                       std::string* output) {
    if (!SafeToken(requestId, L"_-", false) || wcslen(requestId) < 8 ||
        wcslen(requestId) > 128 ||
        timeoutSeconds == 0 || timeoutSeconds > 175)
        return E_INVALIDARG;
    return RunAgent({L"approval-poll", L"--request-id", requestId,
                     L"--timeout", std::to_wstring(timeoutSeconds)}, cancelled, output);
}

void ClearAdApprovalOutput(std::string* output) {
    if (output == nullptr) return;
    if (!output->empty()) SecureZeroMemory(output->data(), output->size());
    output->clear();
}
