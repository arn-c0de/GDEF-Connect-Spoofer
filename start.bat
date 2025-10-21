@echo off
title OrbDef-L1nk - Visualization Software (Admin CMD)

:: Sicherstellen, dass das Skript mit Administratorrechten ausgeführt wird
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Administratorrechte erforderlich. Versuche Neustart mit erhöhten Rechten...
    powershell -Command "Start-Process '%~f0' -Verb runAs"
    exit /b
)

:: Standardausgabe verbessern
chcp 65001 >nul
cls

:: Pfad definieren (aktueller Ordner der BAT-Datei)
set "PROJECT_PATH=%~dp0"
set "PROJECT_PATH=%PROJECT_PATH:~0,-1%"
set "PYTHON_SCRIPT=app.py"
set "VENV_PATH=%PROJECT_PATH%\venv"
set "VENV_PYTHON=%VENV_PATH%\Scripts\python.exe"
set "VENV_ACTIVATE=%VENV_PATH%\Scripts\activate.bat"

:: In Projektverzeichnis wechseln
cd /d "%PROJECT_PATH%" || (
    echo [FEHLER] Projektverzeichnis nicht gefunden: %PROJECT_PATH%
    pause
    exit /b
)

:: Prüfen ob venv existiert
if not exist "%VENV_PATH%" (
    echo [INFO] Virtuelles Environment nicht gefunden. Erstelle venv...
    python -m venv venv || (
        echo [FEHLER] Konnte venv nicht erstellen. Stelle sicher, dass Python installiert ist.
        pause
        exit /b
    )
    echo [INFO] venv erfolgreich erstellt.
    echo.
    echo [INFO] Installiere Abhängigkeiten aus requirements.txt...
    "%VENV_PYTHON%" -m pip install --upgrade pip
    "%VENV_PYTHON%" -m pip install -r requirements.txt || (
        echo [FEHLER] Konnte Abhängigkeiten nicht installieren.
        pause
        exit /b
    )
    echo [INFO] Abhängigkeiten erfolgreich installiert.
    echo.
) else (
    echo [INFO] Virtuelles Environment gefunden: %VENV_PATH%
    echo.
)

:: Anzeigen von Datum und Zeit
echo ============================================
echo   ConnectSpoofer Launcher (Admin Modus)
echo   Datum: %DATE%   Uhrzeit: %TIME%
echo ============================================
echo.

:: Python-Version anzeigen (venv)
echo [INFO] Verwende Python-Version aus venv:
"%VENV_PYTHON%" --version 2>nul || (
    echo [FEHLER] venv Python wurde nicht gefunden.
    pause
    exit /b
)
echo.

:: Netzwerk-Interface Konfiguration prüfen/auswählen
set "BACKEND_CONF=%PROJECT_PATH%\database\backend_conf.json"
if not exist "%BACKEND_CONF%" (
    echo [INFO] Keine Netzwerk-Interface-Konfiguration gefunden.
    echo [INFO] Starte Interface-Auswahl...
    echo.
    "%VENV_PYTHON%" select_interface.py
    if %ERRORLEVEL% neq 0 (
        echo [FEHLER] Interface-Auswahl fehlgeschlagen.
        pause
        exit /b
    )
    echo.
) else (
    echo [INFO] Netzwerk-Interface-Konfiguration gefunden.
    echo [INFO] Drücke 'I' um Interface neu auszuwählen, oder eine beliebige andere Taste zum Fortfahren...
    choice /c IN /n /t 5 /d N >nul
    if %ERRORLEVEL%==1 (
        echo.
        "%VENV_PYTHON%" select_interface.py
        if %ERRORLEVEL% neq 0 (
            echo [FEHLER] Interface-Auswahl fehlgeschlagen.
            pause
            exit /b
        )
        echo.
    )
)

:: Skriptausführung starten
echo [INFO] Starte %PYTHON_SCRIPT% mit venv Python...
echo --------------------------------------------
"%VENV_PYTHON%" "%PYTHON_SCRIPT%"
set "EXIT_CODE=%ERRORLEVEL%"
echo --------------------------------------------

:: Ergebnis anzeigen
if %EXIT_CODE%==0 (
    echo [INFO] app.py wurde erfolgreich beendet.
) else (
    echo [WARNUNG] app.py wurde mit Fehlercode %EXIT_CODE% beendet.
)

:: CMD geöffnet lassen für weitere Befehle
echo.
echo [INFO] Du befindest dich nun in:
cd
echo [INFO] CMD bleibt geöffnet. Du kannst weitere Befehle eingeben.
echo.
cmd /k