@echo off
setlocal
set "ROOT=%ProgramData%\ThessleyPamWin\ad-prototype"
set "PYTHONW=%ProgramFiles%\Python313\pythonw.exe"
if not exist "%PYTHONW%" (
  echo Machine Python with Tkinter was not found at "%PYTHONW%".
  pause
  exit /b 1
)
start "Thessley AD phone enrollment" "%PYTHONW%" -I -X utf8 "%ROOT%\ad_enroll_gui.py"
