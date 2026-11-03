@echo off
setlocal
cd /d "%~dp0"

echo.
echo Building Proxy Control Endpoint GUI v1.3.1...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Build-Proxy-Control-Setup.ps1"
set RC=%ERRORLEVEL%

echo.
if not "%RC%"=="0" (
  echo BUILD FAILED. Exit code: %RC%
) else (
  echo BUILD COMPLETED SUCCESSFULLY.
  echo.
  echo Final installer:
  echo   dist\Proxy-Control-Setup-v1.3.1.exe
)
echo.
pause
exit /b %RC%
