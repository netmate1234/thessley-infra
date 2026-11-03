param(
    [ValidateSet('Hide', 'Restore', 'Status')]
    [string] $Mode = 'Status'
)
$ErrorActionPreference = 'Stop'

$policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$policyName = 'ExcludedCredentialProviders'
$installDir = Join-Path $env:ProgramData 'ThessleyPamWin\ad-credential-provider'
$statePath = Join-Path $installDir 'unused-ad-lab-tiles-state.json'
$hiddenProviderIds = @(
    '{B78189D3-4FE6-4E6B-A143-D63D6436E96B}', # Thessley Passkey unlock (local chip tile)
    '{8FD7E19C-3BF7-489B-A72C-846AB3678C96}', # Windows Smartcard Credential Provider
    '{8A2755BF-64B7-4D39-9C48-67A6A27F5E91}'  # Thessley AD ticket-logon test tile
)

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell session.'
}

function Read-Policy {
    $exists = $false
    $raw = ''
    if (Test-Path -LiteralPath $policyPath) {
        $key = Get-Item -LiteralPath $policyPath
        $exists = $key.GetValueNames() -contains $policyName
        if ($exists) { $raw = [string]$key.GetValue($policyName) }
    }
    $ids = @($raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    return [pscustomobject]@{ Exists = $exists; Raw = $raw; Ids = $ids }
}

function Write-Policy([string[]]$ids, [bool]$exists) {
    if ($exists) {
        if (-not (Test-Path -LiteralPath $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }
        Set-ItemProperty -LiteralPath $policyPath -Name $policyName -Type String -Value ($ids -join ',')
    } else {
        if (Test-Path -LiteralPath $policyPath) {
            Remove-ItemProperty -LiteralPath $policyPath -Name $policyName -ErrorAction SilentlyContinue
        }
    }
}

switch ($Mode) {
    'Status' {
        $policy = Read-Policy
        Write-Output "Hidden unused tiles: $((@($policy.Ids | Where-Object { $_ -in $hiddenProviderIds })).Count) of $($hiddenProviderIds.Count)"
        Write-Output "Current exclusions: $(if ($policy.Ids.Count) { $policy.Ids -join ', ' } else { '(none)' })"
        Write-Output "Saved restore state: $(Test-Path -LiteralPath $statePath)"
        exit 0
    }
    'Hide' {
        if (Test-Path -LiteralPath $statePath) { throw "Restore state already exists: $statePath" }
        $policy = Read-Policy
        $added = @($hiddenProviderIds | Where-Object { $_ -notin $policy.Ids })
        $state = [ordered]@{
            Version = 1
            AddedProviderIds = $added
            OriginalPolicyValueExisted = $policy.Exists
            OriginalPolicyValue = $policy.Raw
            ChangedUtc = [DateTime]::UtcNow.ToString('o')
        }
        $state | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $statePath -Encoding UTF8
        $aclSource = Join-Path $installDir 'ThessleyADCredentialProvider.dll'
        if (Test-Path -LiteralPath $aclSource) {
            Set-Acl -LiteralPath $statePath -AclObject (Get-Acl -LiteralPath $aclSource)
        }
        Write-Policy -ids @($policy.Ids + $added) -exists $true
        $actual = Read-Policy
        if (@($hiddenProviderIds | Where-Object { $_ -notin $actual.Ids }).Count -gt 0) {
            Write-Policy -ids $policy.Ids -exists $policy.Exists
            Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue
            throw 'Could not verify all requested sign-in tiles were hidden; the prior policy was restored.'
        }
        Write-Output 'Hidden the unused local Thessley chip tile, Windows Smartcard tile, and AD ticket-test tile.'
        Write-Output 'The Thessley AD Passkey tile and all pre-existing policy exclusions were preserved.'
        exit 0
    }
    'Restore' {
        if (-not (Test-Path -LiteralPath $statePath -PathType Leaf)) {
            throw 'No saved tile-filter state exists; nothing was changed.'
        }
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.Version -ne 1) { throw 'The saved tile-filter state is not recognized.' }
        $policy = Read-Policy
        $added = @($state.AddedProviderIds)
        $remaining = @($policy.Ids | Where-Object { $_ -notin $added })
        if ($remaining.Count -gt 0) {
            Write-Policy -ids $remaining -exists $true
        } elseif ($state.OriginalPolicyValueExisted) {
            Write-Policy -ids @(([string]$state.OriginalPolicyValue -split ',') |
                ForEach-Object { $_.Trim() } | Where-Object { $_ }) -exists $true
        } else {
            Write-Policy -ids @() -exists $false
        }
        Remove-Item -LiteralPath $statePath -Force
        Write-Output 'Restored the prior tile-filter policy. Other provider exclusions were preserved.'
        exit 0
    }
}
