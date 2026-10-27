@echo off
setlocal
set "LOG=%PUBLIC%\Thessley-enrollment-refresh.txt"
echo Refreshing certificate auto-enrollment in the signed-in domain-user session. > "%LOG%"
certutil.exe -user -pulse >> "%LOG%" 2>&1
set "RESULT=%ERRORLEVEL%"
echo certutil exit code: %RESULT% >> "%LOG%"
type "%LOG%"
echo.
pause
