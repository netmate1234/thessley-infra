@echo off
setlocal
set "ROOT=%ProgramData%\ThessleyPamWin\ad-prototype"
set "PYTHON=%ProgramFiles%\Python313\python.exe"
if not exist "%PYTHON%" (
  echo Machine Python was not found at "%PYTHON%".
  exit /b 1
)
"%PYTHON%" -I -X utf8 "%ROOT%\ad_main.py" %*
exit /b %ERRORLEVEL%
