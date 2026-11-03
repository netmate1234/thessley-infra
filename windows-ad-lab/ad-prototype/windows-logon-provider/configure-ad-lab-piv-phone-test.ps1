[CmdletBinding(DefaultParameterSetName = 'Enable')]
param(
    [Parameter(Mandatory = $true)][string]$Sid,
    [Parameter(Mandatory = $true, ParameterSetName = 'Enable')][string]$ContainerName,
    [Parameter(Mandatory = $true, ParameterSetName = 'Enable')][string]$ReaderName,
    [Parameter(ParameterSetName = 'Enable')][string]$CardName = '',
    [Parameter(ParameterSetName = 'Enable')][string]$ProviderName = 'Microsoft Smart Card Key Storage Provider',
    [Parameter(ParameterSetName = 'Enable')][ValidateSet(1, 2)][int]$KeySpec = 2,
    [Parameter(Mandatory = $true, ParameterSetName = 'Disable')][switch]$Disable
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}
if ($Sid -notmatch '^S-1-(?:[0-9]+-)+[0-9]+$') { throw 'Provide the selected AD account SID.' }
[void][Security.Principal.SecurityIdentifier]::new($Sid)

$relativePath = "SOFTWARE\Thessley\ADCredentialProvider\Users\$Sid"
$usersPath = 'SOFTWARE\Thessley\ADCredentialProvider\Users'
$kspPath = 'SYSTEM\CurrentControlSet\Control\Cryptography\Providers\Microsoft Smart Card Key Storage Provider'
$timeoutName = 'TransactionTimeoutMilliseconds'
$labTimeoutMs = 90000
$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
try {
    $key = $registry.OpenSubKey($relativePath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree)
    if (-not $key) { throw 'Configure the selected AD account with the Thessley provider first.' }
    try {
        if ($Disable) {
            $key.SetValue('PivPhoneSigning', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.DeleteValue('PivPhoneRequestId', $false)
            $savedPresent = $key.GetValue('PivPreviousTransactionTimeoutPresent', $null)
            if ($null -ne $savedPresent) {
                $savedValue = $key.GetValue('PivPreviousTransactionTimeout', $null)
                $ksp = $registry.OpenSubKey($kspPath, $true)
                if (-not $ksp) { throw 'PIV mode is disabled, but the previous smart-card timeout could not be restored.' }
                try {
                    if ($savedPresent -eq 1) {
                        if ($null -eq $savedValue -or [uint64]$savedValue -gt [uint32]::MaxValue) {
                            throw 'PIV mode is disabled, but the saved smart-card timeout value is invalid.'
                        }
                        $ksp.SetValue($timeoutName, [int]$savedValue, [Microsoft.Win32.RegistryValueKind]::DWord)
                    } else {
                        $ksp.DeleteValue($timeoutName, $false)
                    }
                } finally { $ksp.Dispose() }
                $key.DeleteValue('PivPreviousTransactionTimeoutPresent', $false)
                $key.DeleteValue('PivPreviousTransactionTimeout', $false)
            }
            foreach ($name in @('PivContainerName', 'PivProviderName', 'PivReaderName', 'PivCardName', 'PivKeySpec')) {
                $key.DeleteValue($name, $false)
            }
            Write-Output "PIV phone-sign mode disabled for $Sid. The previous smart-card KSP timeout was restored."
            return
        }

        foreach ($entry in @(
            @{ Name = 'ContainerName'; Value = $ContainerName },
            @{ Name = 'ReaderName'; Value = $ReaderName },
            @{ Name = 'ProviderName'; Value = $ProviderName },
            @{ Name = 'CardName'; Value = $CardName }
        )) {
            if ($entry.Value.Length -gt 255 -or $entry.Value -match '[\x00-\x1F\x7F]' -or
                ([string]::IsNullOrWhiteSpace($entry.Value) -and $entry.Name -ne 'CardName')) {
                throw "Invalid PIV $($entry.Name). Required names must be non-empty and at most 255 characters."
            }
        }
        if ($key.GetValue('PivPhoneSigning', 0) -eq 1) {
            throw 'PIV phone-sign mode is already enabled. Disable it before changing its card mapping.'
        }
        $users = $registry.OpenSubKey($usersPath)
        if (-not $users) { throw 'Could not verify that no other account is using the machine-wide PIV test timeout.' }
        try {
            foreach ($otherSid in $users.GetSubKeyNames()) {
                if ($otherSid -eq $Sid) { continue }
                $other = $users.OpenSubKey($otherSid)
                if (-not $other) { continue }
                try {
                    if ($other.GetValue('PivPhoneSigning', 0) -eq 1) {
                        throw "PIV phone-sign mode is already enabled for another account ($otherSid)."
                    }
                } finally { $other.Dispose() }
            }
        } finally { $users.Dispose() }

        $ksp = $registry.OpenSubKey($kspPath, $true)
        if (-not $ksp) { throw 'Could not open the Microsoft smart-card KSP settings.' }
        try {
            $timeoutExists = $ksp.GetValueNames() -contains $timeoutName
            $oldTimeout = if ($timeoutExists) { $ksp.GetValue($timeoutName, $null) } else { $null }
            if ($timeoutExists -and ($null -eq $oldTimeout -or [uint64]$oldTimeout -gt [uint32]::MaxValue)) {
                throw 'The existing smart-card KSP transaction timeout is invalid; no PIV settings were changed.'
            }
            $key.SetValue('PivPreviousTransactionTimeoutPresent', [int]$timeoutExists,
                [Microsoft.Win32.RegistryValueKind]::DWord)
            if ($timeoutExists) {
                $key.SetValue('PivPreviousTransactionTimeout', [int]$oldTimeout,
                    [Microsoft.Win32.RegistryValueKind]::DWord)
            } else {
                $key.DeleteValue('PivPreviousTransactionTimeout', $false)
            }
            $ksp.SetValue($timeoutName, $labTimeoutMs, [Microsoft.Win32.RegistryValueKind]::DWord)
        } finally { $ksp.Dispose() }
        try {
            $key.SetValue('PivContainerName', $ContainerName, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('PivProviderName', $ProviderName, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('PivReaderName', $ReaderName, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('PivCardName', $CardName, [Microsoft.Win32.RegistryValueKind]::String)
            $key.SetValue('PivKeySpec', $KeySpec, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.SetValue('PivPhoneSigning', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
        } catch {
            if ($timeoutExists) {
                $restore = $registry.OpenSubKey($kspPath, $true)
                try { $restore.SetValue($timeoutName, [int]$oldTimeout, [Microsoft.Win32.RegistryValueKind]::DWord) }
                finally { $restore.Dispose() }
            } else {
                $restore = $registry.OpenSubKey($kspPath, $true)
                try { $restore.DeleteValue($timeoutName, $false) } finally { $restore.Dispose() }
            }
            $key.SetValue('PivPhoneSigning', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
            $key.DeleteValue('PivPreviousTransactionTimeoutPresent', $false)
            $key.DeleteValue('PivPreviousTransactionTimeout', $false)
            throw
        }
    } finally { $key.Dispose() }
} finally { $registry.Dispose() }

Write-Output "PIV phone-sign test enabled for SID $Sid. Existing VSC and ticket-test settings were preserved."
Write-Output "Smart-card provider: $ProviderName; Kerberos key spec: $KeySpec."
Write-Output "The machine-wide smart-card KSP timeout is temporarily $labTimeoutMs ms; -Disable restores its prior value."
Write-Output 'This lab mode is interactive sign-in only and never stores the disposable PIN.'
