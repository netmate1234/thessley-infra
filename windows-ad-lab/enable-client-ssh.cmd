@echo off
setlocal
set "THESSLEY_SCRIPT=%~dp0enable-client-ssh.ps1"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'Stop'; try { $p = Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$env:THESSLEY_SCRIPT) -Wait -PassThru; exit $p.ExitCode } catch { Write-Error $_; exit 1 }"
if errorlevel 1 echo Thessley SSH setup did not complete. Read the error above.
pause
