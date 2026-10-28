<#
.SYNOPSIS
  Read-only inspection of Martin's existing TPM virtual-smart-card certificate.
.DESCRIPTION
  Run from an interactive THESSLEYLAB\martin PowerShell session on the joined
  client. The local SSH maintenance identity has a different CurrentUser store.
  This script reads certificate metadata only. It does not enroll, remove,
  export, open, or sign with the private key.
#>
[CmdletBinding()]
param(
    [string]$Thumbprint = '12693C9F323CC1F4C54616237F10ECC2ABA7CBF1'
)

$ErrorActionPreference = 'Stop'
$normalizedThumbprint = ($Thumbprint -replace '\s', '').ToUpperInvariant()

if ($env:USERDOMAIN -ne 'THESSLEYLAB' -or $env:USERNAME -ne 'martin') {
    throw 'Run this read-only check from the interactive THESSLEYLAB\martin session, not the local SSH maintenance account.'
}

$certificate = Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' |
    Where-Object { $_.Thumbprint -eq $normalizedThumbprint } |
    Select-Object -First 1

if (-not $certificate) {
    throw "Certificate $normalizedThumbprint is not visible in this user's Personal certificate store. No certificate was changed."
}

$eku = @(
    foreach ($extension in $certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($oid in $extension.EnhancedKeyUsages) {
                '{0} ({1})' -f $oid.FriendlyName, $oid.Value
            }
        }
    }
)
$keyUsage = @(
    foreach ($extension in $certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            $extension.KeyUsages.ToString()
        }
    }
)

# CERT_KEY_PROV_INFO_PROP_ID is certificate metadata. Reading it does not open
# the provider or ask the TPM virtual card to perform a private-key operation.
$metadataType = 'ThessleyVscCertMetadata_20261028'
if (-not ($metadataType -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class ThessleyVscCertMetadata_20261028
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CRYPT_KEY_PROV_INFO
    {
        public IntPtr ContainerName;
        public IntPtr ProviderName;
        public uint ProviderType;
        public uint Flags;
        public uint ProviderParameterCount;
        public IntPtr ProviderParameters;
        public uint KeySpec;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertGetCertificateContextProperty(
        IntPtr certificate, uint propertyId, IntPtr data, ref uint dataSize);

    public static string[] ReadProviderInfo(IntPtr certificate)
    {
        const uint CERT_KEY_PROV_INFO_PROP_ID = 2;
        uint size = 0;
        CertGetCertificateContextProperty(certificate, CERT_KEY_PROV_INFO_PROP_ID,
            IntPtr.Zero, ref size);
        int error = Marshal.GetLastWin32Error();
        if (size == 0)
            throw new System.ComponentModel.Win32Exception(error,
                "Certificate has no stored key-provider metadata.");

        IntPtr buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            if (!CertGetCertificateContextProperty(certificate,
                    CERT_KEY_PROV_INFO_PROP_ID, buffer, ref size))
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error());

            CRYPT_KEY_PROV_INFO info = Marshal.PtrToStructure<CRYPT_KEY_PROV_INFO>(buffer);
            return new string[] {
                Marshal.PtrToStringUni(info.ProviderName) ?? "",
                Marshal.PtrToStringUni(info.ContainerName) ?? "",
                info.ProviderType.ToString(),
                info.KeySpec.ToString()
            };
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
}
$providerInfo = [ThessleyVscCertMetadata_20261028]::ReadProviderInfo($certificate.Handle)

Write-Host 'Read-only certificate and stored provider metadata' -ForegroundColor Cyan
[pscustomobject]@{
    Subject       = $certificate.Subject
    Issuer        = $certificate.Issuer
    Thumbprint    = $certificate.Thumbprint
    NotBefore     = $certificate.NotBefore
    NotAfter      = $certificate.NotAfter
    HasPrivateKey = $certificate.HasPrivateKey
    EKUs          = $eku -join '; '
    KeyUsage      = $keyUsage -join '; '
    PublicKey     = $certificate.PublicKey.Oid.FriendlyName
    KeyLength     = $certificate.PublicKey.Key.KeySize
    Provider      = $providerInfo[0]
    Container     = $providerInfo[1]
    ProviderType  = $providerInfo[2]
    KeySpec        = $providerInfo[3]
} | Format-List
Write-Host 'No enrollment, removal, export, provider open, or private-key operation was performed.' -ForegroundColor Green
