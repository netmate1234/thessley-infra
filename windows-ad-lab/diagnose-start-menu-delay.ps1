param([ValidateRange(1, 72)][int] $Hours = 8)

$ErrorActionPreference = 'Stop'
$since = (Get-Date).AddHours(-$Hours)

Write-Output '=== Machine ==='
try {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, LastBootUpTime,
            @{Name='FreeMemoryMB';Expression={[math]::Round($_.FreePhysicalMemory / 1024)}},
            @{Name='TotalMemoryMB';Expression={[math]::Round($_.TotalVisibleMemorySize / 1024)}} |
        Format-List
    Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
        Select-Object DisplayVersion, CurrentBuild, UBR, BuildLabEx | Format-List
    Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory |
        Select-Object @{Name='AvailableMB';Expression={[math]::Round($_.AvailableBytes / 1MB)}},
            @{Name='CommittedMB';Expression={[math]::Round($_.CommittedBytes / 1MB)}},
            @{Name='CommitLimitMB';Expression={[math]::Round($_.CommitLimit / 1MB)}},
            PagesInputPersec, PageReadsPersec | Format-List
} catch {
    Write-Warning "Could not read OS/memory status: $($_.Exception.Message)"
}

Write-Output '=== Shell and profile services ==='
try {
    Get-CimInstance Win32_Service -Filter "Name='UserManager' OR Name='ProfSvc' OR Name='StateRepository'" |
        Select-Object Name, State, StartMode, ProcessId, ExitCode, ServiceSpecificExitCode |
        Format-Table -AutoSize
} catch {
    Write-Warning "Could not read service status: $($_.Exception.Message)"
}

Write-Output '=== Thessley sign-in components ==='
try {
    Get-PnpDevice -PresentOnly:$false -ErrorAction Stop |
        Where-Object { $_.FriendlyName -match 'ThessleyADTest|smart.?card|virtual.*card' } |
        Select-Object Status, Present, Class, FriendlyName, InstanceId |
        Format-Table -Wrap
} catch {
    Write-Warning "Could not query smart-card reader devices: $($_.Exception.Message)"
}
try {
    $providerKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{2678765D-9F74-4BDE-A4DA-2B53234BE053}'
    $providerClass = 'HKLM:\SOFTWARE\Classes\CLSID\{2678765D-9F74-4BDE-A4DA-2B53234BE053}\InprocServer32'
    [pscustomobject]@{
        ADLabProviderRegistered = Test-Path -LiteralPath $providerKey
        ADLabProviderDll = if (Test-Path -LiteralPath $providerClass) {
            (Get-ItemProperty -LiteralPath $providerClass).'(default)'
        } else { $null }
    } | Format-List
} catch {
    Write-Warning "Could not query the AD lab provider registration: $($_.Exception.Message)"
}

Write-Output '=== Relevant current processes ==='
try {
    $serviceProcesses = Get-CimInstance Win32_Service -Filter "Name='UserManager' OR Name='ProfSvc' OR Name='StateRepository'" |
        Select-Object -ExpandProperty ProcessId -Unique
    $processes = @(Get-Process -Name StartMenuExperienceHost, ShellExperienceHost, explorer -ErrorAction SilentlyContinue)
    if ($serviceProcesses) {
        $processes += @(Get-Process -Id $serviceProcesses -ErrorAction SilentlyContinue)
    }
    $processes |
        Select-Object ProcessName, Id, StartTime, CPU, Responding,
            @{Name='WorkingSetMB';Expression={[math]::Round($_.WorkingSet64 / 1MB)}} |
        Sort-Object ProcessName, Id | Format-Table -AutoSize
    Write-Output 'Top processes by working set:'
    Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 12 ProcessName, Id,
        @{Name='WorkingSetMB';Expression={[math]::Round($_.WorkingSet64 / 1MB)}} | Format-Table -AutoSize
} catch {
    Write-Warning "Could not read process status: $($_.Exception.Message)"
}

Write-Output "=== Relevant events since $since ==="
$logQueries = @(
    @{Name='Application errors'; Filter=@{LogName='Application'; StartTime=$since; Level=2}; Pattern='Application Error|Windows Error Reporting'; Limit=40},
    @{Name='System errors'; Filter=@{LogName='System'; StartTime=$since; Level=1,2}; Pattern='Service Control Manager|Resource-Exhaustion|Disk|Ntfs|UserManager'; Limit=40},
    @{Name='UserManager service exits'; Filter=@{LogName='System'; StartTime=$since; Id=7031,7034}; Pattern='Service Control Manager'; Limit=30},
    @{Name='User Profile Service'; Filter=@{LogName='Microsoft-Windows-User Profile Service/Operational'; StartTime=$since}; Pattern='User Profile Service'; Limit=30},
    @{Name='Shell Core'; Filter=@{LogName='Microsoft-Windows-Shell-Core/Operational'; StartTime=$since}; Pattern='Shell|StartMenu'; Limit=30}
)
foreach ($query in $logQueries) {
    try {
        $events = Get-WinEvent -FilterHashtable $query.Filter -MaxEvents 500 -ErrorAction Stop
        $matches = $events |
            Where-Object { $_.ProviderName -match $query.Pattern } |
            Select-Object -First $query.Limit TimeCreated, ProviderName, Id, LevelDisplayName,
                @{Name='Message';Expression={($_.Message -replace '[\r\n]+', ' ') -replace '\s{2,}', ' '}}
        if ($matches) {
            Write-Output "--- $($query.Name) ---"
            $matches | Format-List
        }
    } catch {
        Write-Warning "Could not query '$($query.Name)': $($_.Exception.Message)"
    }
}

Write-Output '=== WER dump configuration ==='
try {
    Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\svchost.exe' -ErrorAction Stop |
        Select-Object DumpFolder, DumpType, DumpCount | Format-List
} catch {
    Write-Warning "No readable svchost dump configuration: $($_.Exception.Message)"
}
try {
    Get-ChildItem -LiteralPath 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive' -Directory -ErrorAction Stop |
        Where-Object Name -Match 'AppCrash_svchost\.exe_User' |
        ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -File -ErrorAction SilentlyContinue } |
        Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
} catch {
    Write-Warning "Could not list UserManager WER reports: $($_.Exception.Message)"
}
try {
    Get-ChildItem -LiteralPath 'C:\ProgramData\ThessleyPamWin\diagnostics\dumps' -File -ErrorAction Stop |
        Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
} catch {
    Write-Warning "Could not list Thessley diagnostic dumps: $($_.Exception.Message)"
}
