param(
    [Parameter(Mandatory = $true)][string]$Sid,
    [Parameter(Mandatory = $true)][string]$ContainerName,
    [Parameter(Mandatory = $true)][string]$ProviderName,
    [Parameter(Mandatory = $true)][ValidateSet(1, 2)][int]$KeySpec,
    [string]$ReaderName = '',
    [string]$CardName = ''
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
if ($Sid -notmatch '^S-\d-\d+(?:-\d+)+$') { throw 'Provide the selected AD account SID, not a username.' }
[void][Security.Principal.SecurityIdentifier]::new($Sid)

foreach ($entry in @(
    @{ Name = 'ContainerName'; Value = $ContainerName; Required = $true },
    @{ Name = 'ProviderName'; Value = $ProviderName; Required = $true },
    @{ Name = 'ReaderName'; Value = $ReaderName; Required = $false },
    @{ Name = 'CardName'; Value = $CardName; Required = $false }
)) {
    if ($entry.Value.Length -gt 255 -or $entry.Value -match '[\x00-\x1F\x7F]' -or
        ($entry.Required -and [string]::IsNullOrWhiteSpace($entry.Value))) {
        throw "Invalid $($entry.Name). Required names must be non-empty and names are limited to 255 characters."
    }
}

$relativePath = "SOFTWARE\Thessley\ADCredentialProvider\Users\$Sid"
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    $key = $registry.CreateSubKey($relativePath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
    if (-not $key) { throw 'Could not create the per-account provider configuration.' }
    try {
        $acl = $key.GetAccessControl()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
        $acl.SetAccessRule([Security.AccessControl.RegistryAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), 'FullControl', 'Allow'))
        $acl.SetAccessRule([Security.AccessControl.RegistryAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), 'FullControl', 'Allow'))
        $key.SetAccessControl($acl)

        $key.SetValue('ContainerName', $ContainerName, [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('ProviderName', $ProviderName, [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('ReaderName', $ReaderName, [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('CardName', $CardName, [Microsoft.Win32.RegistryValueKind]::String)
        $key.SetValue('KeySpec', [int]$KeySpec, [Microsoft.Win32.RegistryValueKind]::DWord)
    } finally {
        $key.Dispose()
    }
} finally {
    $registry.Dispose()
}

Write-Output "Per-account VSC mapping saved for SID $Sid. Only SYSTEM and local Administrators can read or change it."
Write-Output 'This config only selects the existing TPM virtual-smart-card key; it does not enable phone-held-key sign-in.'
