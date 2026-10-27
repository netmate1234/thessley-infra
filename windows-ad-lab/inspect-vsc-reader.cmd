@echo off
setlocal
set "LOG=%PUBLIC%\Thessley-VSC-reader-check.txt"
echo Enumerating smart-card readers and card certificates; this does not change the card. > "%LOG%"
certutil.exe -scinfo >> "%LOG%" 2>&1
set "RESULT=%ERRORLEVEL%"
echo certutil exit code: %RESULT% >> "%LOG%"
type "%LOG%"
echo.
pause
