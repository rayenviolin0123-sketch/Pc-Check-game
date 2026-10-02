@echo off
setlocal
cd /d "%~dp0"

:: Re-launch as Administrator if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: Find Python: prefer the 'py' launcher, then 'python'
where py >nul 2>&1 && (set PY=py -3) || (set PY=python)
%PY% --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python was not found. Install it from python.org and tick "Add Python to PATH".
    pause
    exit /b 1
)

set PYTHONUTF8=1
%PY% dma_check.py --json dma_report.json %*
echo.
echo Done. A copy of the results was saved to dma_report.json
pause
