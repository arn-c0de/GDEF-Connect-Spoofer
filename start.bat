@echo off
title GDEF-L1NK - GDEF Suite Network Module (Admin CMD)

:: Ensure the script runs with administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Administrator privileges required. Attempting restart with elevated rights...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

:: Improve default output
chcp 65001 >nul
cls

:: Define path (current folder of the BAT file)
set "PROJECT_PATH=%~dp0"
set "PROJECT_PATH=%PROJECT_PATH:~0,-1%"
set "PYTHON_SCRIPT=app.py"
set "VENV_PATH=%PROJECT_PATH%\.venv"
set "VENV_PYTHON=%VENV_PATH%\Scripts\python.exe"
set "VENV_ACTIVATE=%VENV_PATH%\Scripts\activate.bat"

:: Change to project directory
cd /d "%PROJECT_PATH%" || (
    echo [ERROR] Project directory not found: %PROJECT_PATH%
    pause
    exit /b
)

:: Harden the data directory before anything writes to it. The database folder
:: holds the access token (database\access_token.txt) and the SQLite DB, so it
:: must not be readable by other local users. Remove inherited ACLs and grant
:: full control only to the Administrators group (well-known SID S-1-5-32-544,
:: locale-independent) and the current user.
if not exist "%PROJECT_PATH%\database" mkdir "%PROJECT_PATH%\database"
icacls "%PROJECT_PATH%\database" /inheritance:r /grant:r *S-1-5-32-544:(OI)(CI)F /grant:r "%USERNAME%":(OI)(CI)F >/dev/null 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Could not harden permissions on the database folder.
) else (
    echo [INFO] Hardened database folder permissions ^(Administrators + %USERNAME% only^).
)
echo.

:: Prefer uv when available; fall back to pip for older environments.
where uv >nul 2>&1
if %ERRORLEVEL%==0 (
    echo [INFO] Synchronizing Python environment with uv...
    set "UV_PROJECT_ENVIRONMENT=%VENV_PATH%"
    if exist "%PROJECT_PATH%\uv.lock" (
        uv sync --no-dev --locked
    ) else (
        uv sync --no-dev
    )
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] uv sync failed.
        pause
        exit /b
    )
    echo [INFO] Dependencies synchronized successfully.
    echo.
    goto deps_ready
)

echo [INFO] uv was not found; using the venv/pip fallback.
if not exist "%VENV_PATH%" (
    echo [INFO] Virtual environment not found. Creating .venv...
    python -m venv "%VENV_PATH%" || (
        echo [ERROR] Could not create .venv. Make sure Python 3.11+ is installed.
        pause
        exit /b
    )
)

echo [INFO] Installing dependencies from requirements.txt...
"%VENV_PYTHON%" -m pip install --upgrade pip
"%VENV_PYTHON%" -m pip install -r requirements.txt || (
    echo [ERROR] Could not install dependencies.
    pause
    exit /b
)
echo [INFO] Dependencies installed successfully.
echo.

:deps_ready

:: Display date and time
echo ============================================
echo   GDEF-L1NK - GDEF Suite Network Module
echo   Date: %DATE%   Time: %TIME%
echo ============================================
echo.

:: Show Python version (venv)
echo [INFO] Using Python version from venv:
"%VENV_PYTHON%" --version 2>nul || (
    echo [ERROR] venv Python not found.
    pause
    exit /b
)
echo.

:: Check/select network interface configuration
set "BACKEND_CONF=%PROJECT_PATH%\database\backend_conf.json"
if not exist "%BACKEND_CONF%" (
    echo [INFO] No network interface configuration found.
    echo [INFO] Starting interface selection...
    echo.
    "%VENV_PYTHON%" select_interface.py
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Interface selection failed.
        pause
        exit /b
    )
    echo.
) else (
    echo [INFO] Network interface configuration found.
    echo [INFO] Press 'I' to re-select interface, or any other key to continue...
    choice /c IN /n /t 5 /d N >nul
    if %ERRORLEVEL%==1 (
        echo.
        "%VENV_PYTHON%" select_interface.py
        if %ERRORLEVEL% neq 0 (
            echo [ERROR] Interface selection failed.
            pause
            exit /b
        )
        echo.
    )
)

:: Start script execution
echo [INFO] Starting %PYTHON_SCRIPT% with venv Python...
echo --------------------------------------------
"%VENV_PYTHON%" "%PYTHON_SCRIPT%"
set "EXIT_CODE=%ERRORLEVEL%"
echo --------------------------------------------

:: Show result
if %EXIT_CODE%==0 (
    echo [INFO] app.py exited successfully.
) else (
    echo [WARNING] app.py exited with error code %EXIT_CODE%.
)

:: Keep CMD open for further commands
echo.
echo [INFO] You are now in:
cd
echo [INFO] CMD remains open. You can enter further commands.
echo.
cmd /k
