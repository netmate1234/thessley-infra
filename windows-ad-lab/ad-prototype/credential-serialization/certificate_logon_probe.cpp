// Disposable lab probe: ask the Windows Kerberos package to perform an
// interactive certificate logon using a specified CryptoAPI/CNG key
// container. It writes no certificate, key, PIN, or token data to disk.
// Run only as LocalSystem on a disposable domain-joined test client.

#include <windows.h>
#include <ntsecapi.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>

#include "kerb_certificate_serialization.h"

namespace {

void PrintStatus(const char* label, NTSTATUS status) {
    std::printf("%s=0x%08lx\n", label,
                static_cast<unsigned long>(status));
}

bool ValidName(const wchar_t* value, size_t limit) {
    if (!value || !*value || std::wcslen(value) > limit) return false;
    for (const wchar_t* p = value; *p; ++p) {
        if (*p < 0x20 || *p == 0x7f) return false;
    }
    return true;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 6) {
        std::fputs("usage: certificate_logon_probe.exe <domain> <user> <container> <provider> <key-spec-1-or-2>\n",
                   stderr);
        return 2;
    }
    if (!ValidName(argv[1], 255) || !ValidName(argv[2], 255) ||
        !ValidName(argv[3], 255) || !ValidName(argv[4], 255)) {
        std::fputs("domain, user, container and provider must be bounded non-empty names\n",
                   stderr);
        return 2;
    }
    wchar_t* end = nullptr;
    const unsigned long keySpecValue = std::wcstoul(argv[5], &end, 10);
    if (end == argv[5] || *end != L'\0' ||
        (keySpecValue != AT_KEYEXCHANGE && keySpecValue != AT_SIGNATURE)) {
        std::fputs("key-spec must be 1 or 2\n", stderr);
        return 2;
    }

    LSA_STRING processName{};
    char processNameBuffer[] = "ThessleyCertLogonProbe";
    processName.Buffer = processNameBuffer;
    processName.Length = static_cast<USHORT>(sizeof(processNameBuffer) - 1);
    processName.MaximumLength = static_cast<USHORT>(sizeof(processNameBuffer));

    HANDLE lsa = nullptr;
    ULONG securityMode = 0;
    NTSTATUS status = LsaRegisterLogonProcess(&processName, &lsa,
                                               &securityMode);
    if (status < 0) {
        PrintStatus("register_logon_process", status);
        return 3;
    }

    LSA_STRING packageName{};
    char kerberosName[] = MICROSOFT_KERBEROS_NAME_A;
    packageName.Buffer = kerberosName;
    packageName.Length = static_cast<USHORT>(sizeof(kerberosName) - 1);
    packageName.MaximumLength = static_cast<USHORT>(sizeof(kerberosName));
    ULONG packageId = 0;
    status = LsaLookupAuthenticationPackage(lsa, &packageName, &packageId);
    if (status < 0) {
        PrintStatus("lookup_kerberos_package", status);
        LsaDeregisterLogonProcess(lsa);
        return 4;
    }

    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
    const CLSID probeClsid = {0x341d2b0e, 0x1e18, 0x4f39,
                              {0xa3, 0x1f, 0xf3, 0xb2, 0x59, 0x7c, 0x0c, 0x72}};
    const HRESULT buildHr = BuildKerbCertificateSerialization(
        argv[1], argv[2], L"", L"", L"", argv[3], argv[4],
        static_cast<DWORD>(keySpecValue), false, nullptr, packageId,
        probeClsid, &serialization, true);
    if (FAILED(buildHr)) {
        std::printf("build_serialization=0x%08lx\n",
                    static_cast<unsigned long>(buildHr));
        LsaDeregisterLogonProcess(lsa);
        return 5;
    }

    TOKEN_SOURCE source{};
    std::memcpy(source.SourceName, "TSHLYCRT", sizeof(source.SourceName));
    if (!AllocateLocallyUniqueId(&source.SourceIdentifier)) {
        std::printf("allocate_token_source=0x%08lx\n",
                    static_cast<unsigned long>(GetLastError()));
        FreeKerbCertificateSerialization(&serialization);
        LsaDeregisterLogonProcess(lsa);
        return 6;
    }

    LSA_STRING origin{};
    char originName[] = "ThessleyCertLogonProbe";
    origin.Buffer = originName;
    origin.Length = static_cast<USHORT>(sizeof(originName) - 1);
    origin.MaximumLength = static_cast<USHORT>(sizeof(originName));
    PVOID profile = nullptr;
    ULONG profileBytes = 0;
    LUID logonId{};
    HANDLE token = nullptr;
    QUOTA_LIMITS quotas{};
    NTSTATUS subStatus = 0;

    status = LsaLogonUser(
        lsa, &origin, Interactive, serialization.ulAuthenticationPackage,
        serialization.rgbSerialization, serialization.cbSerialization,
        nullptr, &source, &profile, &profileBytes, &logonId, &token,
        &quotas, &subStatus);
    PrintStatus("lsa_logon_user", status);
    PrintStatus("lsa_substatus", subStatus);
    std::printf("serialization_bytes=%lu\n",
                static_cast<unsigned long>(serialization.cbSerialization));
    std::printf("profile_bytes=%lu\n", static_cast<unsigned long>(profileBytes));
    std::printf("logon_luid=%08lx:%08lx\n",
                static_cast<unsigned long>(logonId.HighPart),
                static_cast<unsigned long>(logonId.LowPart));

    if (profile) LsaFreeReturnBuffer(profile);
    if (token) CloseHandle(token);
    FreeKerbCertificateSerialization(&serialization);
    LsaDeregisterLogonProcess(lsa);
    return status >= 0 && subStatus >= 0 ? 0 : 7;
}
