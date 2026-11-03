param(
    [ValidateSet('Remove', 'Restore', 'Status')]
    [string] $Mode = 'Status'
)
$ErrorActionPreference = 'Stop'

$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider'
$backupDir = Join-Path $installDir 'unused-provider-registration-backup'
$statePath = Join-Path $backupDir 'state.json'
$providers = @(
    [pscustomobject]@{ Name = 'Thessley local chip tile'; Id = '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}' },
    [pscustomobject]@{ Name = 'Thessley AD ticket-test tile'; Id = '{8A2755BF-64B7-4D39-9C48-67A6A27F5E91}' }
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

$registryPaths = @(
    'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers',
    'SOFTWARE\Classes\CLSID'
)

switch ($Mode) {
    'Status' {
        foreach ($provider in $providers) {
            $cp = "Registry::HKEY_LOCAL_MACHINE\$($registryPaths[0])\$($provider.Id)"
            $clsid = "Registry::HKEY_LOCAL_MACHINE\$($registryPaths[1])\$($provider.Id)"
            [pscustomobject]@{ Tile = $provider.Name; CredentialProviderRegistered = (Test-Path $cp); ComClassRegistered = (Test-Path $clsid) }
        }
        Write-Output "Saved restore data: $(Test-Path -LiteralPath $statePath)"
        exit 0
    }
    'Remove' {
        if (Test-Path -LiteralPath $statePath) { throw "Restore data already exists: $statePath" }
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        $entries = @()
        try {
            foreach ($provider in $providers) {
                foreach ($root in $registryPaths) {
                    $keyPath = "$root\$($provider.Id)"
                    $nativePath = "HKLM\$keyPath"
                    $backup = Join-Path $backupDir (($provider.Id.Trim('{}')) + '-' + $(if ($root -eq $registryPaths[0]) { 'credential-provider' } else { 'clsid' }) + '.reg')
                    $exists = Test-Path "Registry::HKEY_LOCAL_MACHINE\$keyPath"
                    if ($exists) {
                        & reg.exe export $nativePath $backup /y | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw "Could not back up registry key $nativePath" }
                    }
                    $entries += [pscustomobject]@{ KeyPath = $keyPath; BackupFile = $backup; Existed = $exists }
                }
            }
            [ordered]@{ Version = 1; Entries = $entries } |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
            foreach ($entry in $entries) {
                if ($entry.Existed) {
                    Remove-Item -LiteralPath "Registry::HKEY_LOCAL_MACHINE\$($entry.KeyPath)" -Recurse -Force
                }
            }
            foreach ($entry in $entries) {
                if (Test-Path "Registry::HKEY_LOCAL_MACHINE\$($entry.KeyPath)") {
                    throw "Provider registration remains after removal: $($entry.KeyPath)"
                }
            }
        } catch {
            if (Test-Path -LiteralPath $statePath) {
                $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
                foreach ($entry in $state.Entries) {
                    if ($entry.Existed -and (Test-Path -LiteralPath $entry.BackupFile)) {
                        & reg.exe import $entry.BackupFile | Out-Null
                    }
                }
            }
            throw
        }
        Write-Output 'Removed the local chip and AD ticket-test providers from Windows Credential Provider registration.'
        Write-Output "Registry backups retained at: $backupDir"
        Write-Output 'The Thessley AD Passkey provider was not changed.'
        Write-Output 'To restore these providers, run this script with -Mode Restore, then run configure-unused-ad-lab-tiles.ps1 -Mode Restore.'
        exit 0
    }
    'Restore' {
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) { throw 'No saved provider registration backup exists.' }
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.Version -ne 1) { throw 'The provider registration backup is not recognized.' }
        foreach ($entry in $state.Entries) {
            if ($entry.Existed) {
                if (-not (Test-Path -LiteralPath $entry.BackupFile)) { throw "Registry backup is missing: $($entry.BackupFile)" }
                & reg.exe import $entry.BackupFile | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "Could not restore registry key $($entry.KeyPath)" }
            }
        }
        Write-Output 'The saved local chip and AD ticket-test provider registrations were restored.'
        Write-Output 'Run configure-unused-ad-lab-tiles.ps1 -Mode Restore to remove their exclusion entries.'
        exit 0
    }
}
