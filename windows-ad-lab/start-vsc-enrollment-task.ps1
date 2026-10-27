param([string] $HelperName = 'request-vsc-certificate.cmd')

# Launch a helper in the already-signed-in domain user's desktop session.
# Run elevated over the client's management SSH session.
$ErrorActionPreference = 'Stop'
$taskName = 'Thessley-ADLab-VSC-Enrollment-Interactive'
$scriptPath = Join-Path $env:PUBLIC (Join-Path 'Desktop' $HelperName)
if (-not (Test-Path -LiteralPath $scriptPath)) { throw "Enrollment helper not found: $scriptPath" }

Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute "$env:WINDIR\System32\cmd.exe" -Argument "/c `"$scriptPath`""
$principal = New-ScheduledTaskPrincipal -UserId 'THESSLEYLAB\martin' -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2
Get-ScheduledTask -TaskName $taskName | Select-Object TaskName, State
