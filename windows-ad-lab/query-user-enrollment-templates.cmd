@echo off
setlocal
set "LOG=%PUBLIC%\Thessley-enrollment-templates.txt"
certutil.exe -user -Template > "%LOG%" 2>&1
type "%LOG%"
echo.
pause
