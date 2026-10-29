param(
    [string] $InstallRoot = "$env:ProgramFiles\ThessleyAD",
    [string] $StateRoot = "$env:ProgramData\ThessleyAD",
    [string] $BindAddress = '192.168.1.79',
    [string] $AllowedGroupSid = 'S-1-5-21-1719900462-4250469598-2954734011-1105',
    [string[]] $AllowedRemoteAddresses = @(),
    [string[]] $AdminAllowedRemoteAddresses = @()
)
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this installer from an elevated PowerShell session.'
}
if (-not (Get-Service -Name ADWS -ErrorAction SilentlyContinue)) {
    throw 'The Active Directory Web Services are missing; this host does not appear to be a domain controller.'
}
$address = [ipaddress]::Parse($BindAddress)
if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    -not (Get-NetIPAddress -AddressFamily IPv4 -IPAddress $BindAddress -ErrorAction SilentlyContinue)) {
    throw "Bind address $BindAddress is not assigned to this DC. No service changes were made."
}
if ($AllowedGroupSid -notmatch '^S-1-(?:\d+-)+\d+$') { throw 'AllowedGroupSid must be a canonical AD group SID.' }
foreach ($source in (@($AllowedRemoteAddresses) + @($AdminAllowedRemoteAddresses))) {
    if ($source -match '^(.+)/(\d{1,2})$') {
        $sourceAddress = $null
        if (-not [Net.IPAddress]::TryParse($Matches[1], [ref]$sourceAddress) -or
            $sourceAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
            [int]$Matches[2] -lt 1 -or [int]$Matches[2] -gt 32) {
            throw "A remote-address setting contains an invalid IPv4 CIDR: $source"
        }
    } else {
        $sourceAddress = $null
        if (-not [Net.IPAddress]::TryParse($source, [ref]$sourceAddress) -or
            $sourceAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Remote-address settings must contain IPv4 addresses or CIDRs: $source"
        }
    }
}
$rootDse = [ADSI]'LDAP://RootDSE'
$baseDn = [string]$rootDse.Properties['defaultNamingContext'][0]
if ([string]::IsNullOrWhiteSpace($baseDn)) { throw 'Could not read the AD naming context.' }
$groupSid = [Security.Principal.SecurityIdentifier]::new($AllowedGroupSid)
$groupSidBytes = New-Object byte[] $groupSid.BinaryLength
$groupSid.GetBinaryForm($groupSidBytes, 0)
$groupSidFilter = -join ($groupSidBytes | ForEach-Object { '\' + $_.ToString('X2') })
$groupSearch = [System.DirectoryServices.DirectorySearcher]::new([ADSI]"LDAP://$baseDn")
$groupSearch.Filter = "(&(objectCategory=group)(objectSid=$groupSidFilter)(groupType:1.2.840.113556.1.4.803:=2147483648))"
[void]$groupSearch.PropertiesToLoad.Add('objectSid')
[void]$groupSearch.PropertiesToLoad.Add('sAMAccountName')
$group = $groupSearch.FindOne()
if (-not $group -or [Security.Principal.SecurityIdentifier]::new([byte[]]$group.Properties['objectsid'][0], 0).Value -ne $AllowedGroupSid) {
    $groupSearch.Dispose()
    throw 'AllowedGroupSid does not identify a security group in this AD domain.'
}
$groupName = [string]$group.Properties['samaccountname'][0]
$groupSearch.Dispose()

$sourceRoot = $PSScriptRoot
$appSource = Join-Path $sourceRoot 'package'
if (-not (Test-Path (Join-Path $appSource 'thessley_ad_service\windows_service.py'))) {
    throw 'The verified service package is missing beside this installer.'
}
$python = Join-Path $InstallRoot 'Python\python.exe'
$pythonInstaller = Join-Path $sourceRoot 'install-python.ps1'
if (-not (Test-Path -LiteralPath $pythonInstaller)) { throw 'The pinned Python installer is missing.' }
# Run on upgrades too: an existing Python runtime may lack a newly required,
# pinned package such as qrcode. The installer validates Python and reconciles
# service dependencies before the live app or task is touched.
& $pythonInstaller -InstallRoot (Join-Path $InstallRoot 'Python')
if ($LASTEXITCODE -ne 0) { throw 'Pinned Python setup failed.' }
if (-not (Test-Path -LiteralPath $python)) { throw "Pinned Python was not installed at $python." }

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
New-Item -ItemType Directory -Path $StateRoot -Force | Out-Null
& icacls.exe $InstallRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the AD service installation folder.' }
& icacls.exe $StateRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the AD service state folder.' }

$staging = Join-Path $InstallRoot 'app.staging'
$live = Join-Path $InstallRoot 'app'
if (Test-Path $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging -Force | Out-Null
Copy-Item -Path (Join-Path $appSource '*') -Destination $staging -Recurse -Force
$env:PYTHONPATH = $staging
& $python -I -m compileall -q $staging
if ($LASTEXITCODE -ne 0) { throw 'The staged Python service failed its compile check; live files remain unchanged.' }

$configPath = Join-Path $StateRoot 'service.json'
if (-not (Test-Path $configPath)) {
    $config = [ordered]@{
        version = 1
        bind_address = $BindAddress
        public_host = $BindAddress
        authority = 'THESSLEYLAB'
        allowed_group_sids = @($AllowedGroupSid)
    }
    $json = $config | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText($configPath, $json + "`n", [Text.UTF8Encoding]::new($false))
} else {
    Write-Warning 'Existing service.json retained. Review its bind address and group SID before starting.'
}
& icacls.exe $StateRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the AD service state files.' }

$taskName = 'ThessleyADApi'
$previousTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
$previousTaskXml = if ($previousTask) { Export-ScheduledTask -TaskName $taskName }
$previousTaskWasRunning = $previousTask -and $previousTask.State -eq 'Running'
$backup = $null
$stateBackup = $null
$movedPreviousApp = $false
$createdFirewallRule = $false
$modifiedFirewallRule = $false
$createdAdminFirewallRule = $false
$modifiedAdminFirewallRule = $false
$oldFirewallRemoteAddresses = $null
$oldFirewallProfiles = $null
$oldAdminFirewallRemoteAddresses = $null
$oldAdminFirewallProfiles = $null
$ruleName = 'Thessley AD API TCP 47810 (LAN)'
$adminRuleName = 'Thessley AD Admin TCP 47820 (LAN)'

try {
    if ($previousTaskWasRunning) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $stopDeadline = (Get-Date).AddSeconds(25)
        do {
            Start-Sleep -Milliseconds 500
            $currentTask = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        } while ($currentTask.State -eq 'Running' -and (Get-Date) -lt $stopDeadline)
        if ($currentTask.State -eq 'Running') {
            Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            throw 'The existing API task did not stop; the live application was left unchanged.'
        }
    }

    # Keep an explicit, ACL-inheriting snapshot of persistent identity and
    # enrollment state before replacing the app. This includes the machine and
    # phone public-key database and the TLS identity; it never copies private
    # phone keys because those remain on the phones.
    $stateBackupRoot = Join-Path $StateRoot 'backups'
    $stateBackup = Join-Path $stateBackupRoot ("pre-update-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $stateBackup -Force | Out-Null
    foreach ($stateFile in @('state.sqlite3', 'service.json', 'https-cert.pem', 'https-key.pem')) {
        $statePath = Join-Path $StateRoot $stateFile
        if (Test-Path -LiteralPath $statePath -PathType Leaf) {
            Copy-Item -LiteralPath $statePath -Destination (Join-Path $stateBackup $stateFile) -ErrorAction Stop
        }
    }

    if (Test-Path $live) {
        $backup = Join-Path $InstallRoot ("app.backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
        Move-Item -LiteralPath $live -Destination $backup
        $movedPreviousApp = $true
    }
    Move-Item -LiteralPath $staging -Destination $live

$taskAction = New-ScheduledTaskAction -Execute $python `
    -Argument "-I `"$live\run_windows_service.py`"" -WorkingDirectory $InstallRoot
$trigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Seconds 10)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'Thessley AD QR sign-in API (lab only)' -Force | Out-Null

    $firewallRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($firewallRule) {
        if ($AllowedRemoteAddresses.Count -gt 0) {
            $oldFirewallRemoteAddresses = @(($firewallRule | Get-NetFirewallAddressFilter).RemoteAddress)
            $oldFirewallProfiles = $firewallRule.Profile
            $modifiedFirewallRule = $true
            Set-NetFirewallRule -InputObject $firewallRule -Profile Any | Out-Null
            $firewallRule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $AllowedRemoteAddresses | Out-Null
        }
    } else {
        $newRemoteAddresses = if ($AllowedRemoteAddresses.Count -gt 0) { $AllowedRemoteAddresses } else { @('192.168.1.0/24') }
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47810 `
            -LocalAddress $BindAddress -RemoteAddress $newRemoteAddresses -Profile Any | Out-Null
        $createdFirewallRule = $true
    }

    # The browser admin page is a separate listener and firewall rule. On a
    # first install it follows the API source scope unless an admin-specific
    # list is supplied. On upgrades, preserve an existing admin rule unless
    # its own scope is explicitly changed.
    $adminFirewallRule = Get-NetFirewallRule -DisplayName $adminRuleName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($adminFirewallRule) {
        if ($AdminAllowedRemoteAddresses.Count -gt 0) {
            $oldAdminFirewallRemoteAddresses = @(($adminFirewallRule | Get-NetFirewallAddressFilter).RemoteAddress)
            $oldAdminFirewallProfiles = $adminFirewallRule.Profile
            $modifiedAdminFirewallRule = $true
            Set-NetFirewallRule -InputObject $adminFirewallRule -Profile Any | Out-Null
            $adminFirewallRule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $AdminAllowedRemoteAddresses | Out-Null
        }
    } else {
        if ($AdminAllowedRemoteAddresses.Count -gt 0) {
            $adminRemoteAddresses = $AdminAllowedRemoteAddresses
        } elseif ($AllowedRemoteAddresses.Count -gt 0) {
            $adminRemoteAddresses = $AllowedRemoteAddresses
        } elseif ($firewallRule) {
            $adminRemoteAddresses = @(($firewallRule | Get-NetFirewallAddressFilter).RemoteAddress)
        } else {
            $adminRemoteAddresses = @('192.168.1.0/24')
        }
        New-NetFirewallRule -DisplayName $adminRuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47820 `
            -LocalAddress $BindAddress -RemoteAddress $adminRemoteAddresses -Profile Any | Out-Null
        $createdAdminFirewallRule = $true
    }

Start-ScheduledTask -TaskName $taskName
    $listener = $null
    $adminListener = $null
    $startDeadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 500
        $listener = Get-NetTCPConnection -State Listen -LocalAddress $BindAddress -LocalPort 47810 -ErrorAction SilentlyContinue
        $adminListener = Get-NetTCPConnection -State Listen -LocalAddress $BindAddress -LocalPort 47820 -ErrorAction SilentlyContinue
    } while ((-not $listener -or -not $adminListener) -and (Get-Date) -lt $startDeadline)
if (-not $listener -or -not $adminListener) {
    $task = Get-ScheduledTask -TaskName $taskName
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    $log = Join-Path $StateRoot 'service.log'
    $detail = if (Test-Path $log) { (Get-Content $log -Tail 20 -ErrorAction SilentlyContinue) -join "`n" } else { 'No service log was created.' }
    throw "AD service listeners did not start on $BindAddress`:47810 and :47820 (task $($task.State), result $($info.LastTaskResult)). $detail"
}
if (-not (Test-Path (Join-Path $StateRoot 'https-cert.pem'))) { throw 'The service listener started without creating its TLS identity.' }
$certificatePin = & $python -I -c "import hashlib; from cryptography import x509; from cryptography.hazmat.primitives import serialization; print(hashlib.sha256(x509.load_pem_x509_certificate(open(r'$StateRoot\https-cert.pem','rb').read()).public_bytes(serialization.Encoding.DER)).hexdigest())"
if ($LASTEXITCODE -ne 0 -or $certificatePin.Trim() -notmatch '^[0-9a-f]{64}$') {
    throw 'Could not read the service certificate fingerprint.'
}
$adminCommand = Join-Path $InstallRoot 'thessley-ad-admin.cmd'
$adminCmdText = "@echo off`r`n`"$python`" -I `"$live\run_windows_admin.py`" %*`r`nexit /b %ERRORLEVEL%`r`n"
[IO.File]::WriteAllText($adminCommand, $adminCmdText, [Text.Encoding]::ASCII)
& icacls.exe $adminCommand /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the local admin command file.' }
} catch {
    $failure = $_
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $stopDeadline = (Get-Date).AddSeconds(15)
    do {
        Start-Sleep -Milliseconds 500
        $currentTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    } while ($currentTask -and $currentTask.State -eq 'Running' -and (Get-Date) -lt $stopDeadline)
    if ($movedPreviousApp) {
        if (Test-Path $live) { Remove-Item -LiteralPath $live -Recurse -Force -ErrorAction SilentlyContinue }
        Move-Item -LiteralPath $backup -Destination $live -ErrorAction SilentlyContinue
    } elseif (-not $previousTask -and (Test-Path $live)) {
        Remove-Item -LiteralPath $live -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($previousTaskXml) {
        Register-ScheduledTask -TaskName $taskName -Xml $previousTaskXml -Force -ErrorAction SilentlyContinue | Out-Null
        if ($previousTaskWasRunning) { Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    } else {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($createdFirewallRule) {
        Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    } elseif ($modifiedFirewallRule) {
        $firewallRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($firewallRule) {
            Set-NetFirewallRule -InputObject $firewallRule -Profile $oldFirewallProfiles -ErrorAction SilentlyContinue | Out-Null
            $firewallRule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $oldFirewallRemoteAddresses -ErrorAction SilentlyContinue | Out-Null
        }
    }
    if ($createdAdminFirewallRule) {
        Get-NetFirewallRule -DisplayName $adminRuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    } elseif ($modifiedAdminFirewallRule) {
        $adminFirewallRule = Get-NetFirewallRule -DisplayName $adminRuleName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($adminFirewallRule) {
            Set-NetFirewallRule -InputObject $adminFirewallRule -Profile $oldAdminFirewallProfiles -ErrorAction SilentlyContinue | Out-Null
            $adminFirewallRule | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter -RemoteAddress $oldAdminFirewallRemoteAddresses -ErrorAction SilentlyContinue | Out-Null
        }
    }
    throw $failure
}
Write-Host "Installed the Thessley AD API and management site. Test https://$BindAddress`:47810 from the phone and client."
Write-Host "Administrator site: https://$BindAddress`:47820/admin/ (sign in as a domain controller administrator)."
if ($stateBackup) { Write-Host "Pre-update service state backup: $stateBackup" }
Write-Host "TLS certificate SHA-256: $($certificatePin.Trim())"
Write-Host "Issue a machine code with: `"$adminCommand`" issue-machine-code"
Write-Host "AD allow group: $groupName ($AllowedGroupSid)"
if ($AllowedRemoteAddresses.Count -gt 0) {
    Write-Host "AD API TCP 47810 source filter set to: $($AllowedRemoteAddresses -join ', ')"
} else {
    Write-Host 'AD API firewall source scope preserved (or defaults to 192.168.1.0/24 on first install).'
}
if ($AdminAllowedRemoteAddresses.Count -gt 0) {
    Write-Host "Admin TCP 47820 source filter set to: $($AdminAllowedRemoteAddresses -join ', ')"
} else {
    Write-Host 'Admin TCP 47820 uses its existing scope or follows the AD API source scope on first install.'
}
Write-Host 'This does not install or change a Windows sign-in tile.'
