@echo off
setlocal
set "LOG=%PUBLIC%\Thessley-VSC-enrollment.txt"
echo Requesting the ThessleyVscLogon certificate as the signed-in domain user. > "%LOG%"
certreq.exe -enroll -user -q ThessleyVscLogon >> "%LOG%" 2>&1
set "RESULT=%ERRORLEVEL%"
echo certreq exit code: %RESULT% >> "%LOG%"
type "%LOG%"
echo.
pause
