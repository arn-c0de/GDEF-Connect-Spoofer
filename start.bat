@echo off
title OrbDef-L1nk - Visualization Software (Admin CMD)

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
set "VENV_PATH=%PROJECT_PATH%\venv"
set "VENV_PYTHON=%VENV_PATH%\Scripts\python.exe"
set "VENV_ACTIVATE=%VENV_PATH%\Scripts\activate.bat"

:: Change to project directory
cd /d "%PROJECT_PATH%" || (
    echo [ERROR] Project directory not found: %PROJECT_PATH%
    pause
    exit /b
)

:: Check if venv exists
if not exist "%VENV_PATH%" (
    echo [INFO] Virtual environment not found. Creating venv...
    python -m venv venv || (
        echo [ERROR] Could not create venv. Make sure Python is installed.
        pause
        exit /b
    )
    echo [INFO] venv created successfully.
    echo.
    echo [INFO] Installing dependencies from requirements.txt...
    "%VENV_PYTHON%" -m pip install --upgrade pip
    "%VENV_PYTHON%" -m pip install -r requirements.txt || (
        echo [ERROR] Could not install dependencies.
        pause
        exit /b
    )
    echo [INFO] Dependencies installed successfully.
    echo.
) else (
    echo [INFO] Virtual environment found: %VENV_PATH%
    echo.
)

:: Display date and time
echo ============================================
echo   ConnectSpoofer Launcher (Admin Mode)
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
