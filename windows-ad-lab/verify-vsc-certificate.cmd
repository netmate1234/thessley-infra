@echo off
setlocal
set "LOG=%PUBLIC%\Thessley-VSC-certificate-check.txt"
echo Checking the current user's certificate store and TPM smart-card provider. > "%LOG%"
certutil.exe -user -store My >> "%LOG%" 2>&1
set "RESULT=%ERRORLEVEL%"
echo certutil exit code: %RESULT% >> "%LOG%"
type "%LOG%"
echo.
pause
