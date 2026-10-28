param(
    [string] $InstallRoot = "$env:ProgramFiles\ThessleyAD",
    [string] $StateRoot = "$env:ProgramData\ThessleyAD",
    [string] $BindAddress = '192.168.1.79',
    [string] $AllowedGroupSid = 'S-1-5-21-1719900462-4250469598-2954734011-1105'
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
if (-not (Test-Path -LiteralPath $python)) {
    $pythonInstaller = Join-Path $sourceRoot 'install-python.ps1'
    if (-not (Test-Path -LiteralPath $pythonInstaller)) { throw 'The pinned Python installer is missing.' }
    & $pythonInstaller -InstallRoot (Join-Path $InstallRoot 'Python')
    if ($LASTEXITCODE -ne 0) { throw 'Pinned Python setup failed.' }
}

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
$movedPreviousApp = $false
$createdFirewallRule = $false
$ruleName = 'Thessley AD API TCP 47810 (LAN)'

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

    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 47810 `
            -LocalAddress $BindAddress -RemoteAddress '192.168.1.0/24' -Profile Domain,Private | Out-Null
        $createdFirewallRule = $true
    }

Start-ScheduledTask -TaskName $taskName
    $listener = $null
    $startDeadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 500
        $listener = Get-NetTCPConnection -State Listen -LocalAddress $BindAddress -LocalPort 47810 -ErrorAction SilentlyContinue
        $currentTask = Get-ScheduledTask -TaskName $taskName
        if (-not $listener -and $currentTask.State -ne 'Running') { break }
    } while (-not $listener -and (Get-Date) -lt $startDeadline)
if (-not $listener) {
    $task = Get-ScheduledTask -TaskName $taskName
    $info = Get-ScheduledTaskInfo -TaskName $taskName
    $log = Join-Path $StateRoot 'service.log'
    $detail = if (Test-Path $log) { (Get-Content $log -Tail 20 -ErrorAction SilentlyContinue) -join "`n" } else { 'No service log was created.' }
    throw "AD API did not listen on $BindAddress`:47810 (task $($task.State), result $($info.LastTaskResult)). $detail"
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
    }
    throw $failure
}
Write-Host "Installed the isolated Thessley AD API task. Test https://$BindAddress`:47810 from the phone and client."
Write-Host "TLS certificate SHA-256: $($certificatePin.Trim())"
Write-Host "Issue a machine code with: `"$adminCommand`" issue-machine-code"
Write-Host "AD allow group: $groupName ($AllowedGroupSid)"
Write-Host 'This does not install or change a Windows sign-in tile.'
