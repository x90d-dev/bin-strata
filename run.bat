@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title bin-strata : static pe structural dissector

echo ============================================================
echo   [ bin-strata : static pe structural dissector ]
echo ============================================================

where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARN] Python 3.8+ was not found on your system PATH.
    echo [INFO] Please install Python 3.8 or newer and enable "Add Python to PATH".
    pause
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARN] Python 3.8 or newer is required to run bin-strata.
    python --version
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Creating isolated virtual environment in .venv ...
    python -m venv .venv
)

if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
)

if exist "requirements.txt" (
    python -m pip install --quiet --disable-pip-version-check --upgrade -r requirements.txt >nul 2>&1
)

python main.py %*

echo.
pause
endlocal
