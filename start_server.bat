@echo off
title MusicianHub Server Launcher
color 0A

echo ========================================================
echo                MUSICIANHUB SERVER LAUNCHER
echo ========================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.8+ from python.org
    echo.
    pause
    exit /b 1
)

echo [1/4] Checking Python installation...
python --version
echo.

echo [2/4] Installing required packages...
pip install flask flask-sqlalchemy flask-login werkzeug >nul 2>&1
if errorlevel 1 (
    echo WARNING: Failed to install packages automatically.
    echo You may need to run: pip install flask flask-sqlalchemy flask-login werkzeug
    echo.
) else (
    echo ✓ Packages installed successfully
)

echo.
echo [3/4] Opening firewall port 5000...
netsh advfirewall firewall add rule name="MusicianHub Flask Port 5000" dir=in action=allow protocol=TCP localport=5000 >nul 2>&1
echo ✓ Firewall configured

echo.
echo [4/4] Getting network information...
for /f "tokens=2 delims=:" %%i in ('ipconfig ^| findstr "IPv4" ^| findstr "192"') do set IP=%%i
set IP=%IP: =%
echo.
echo ========================================================
echo                SERVER STARTING...
echo ========================================================
echo.
echo 📍 YOUR ACCESS LINKS:
echo    This PC:     http://localhost:5000
echo    Network:     http://%IP%:5000
echo.
echo 📱 On other devices (phone/tablet/PC):
echo    Open browser and go to: http://%IP%:5000
echo.
echo 👤 Demo accounts (email / password):
echo    demo1@musicianhub.com / Music123! (Admin)
echo    demo2@musicianhub.com / Music123!
echo    demo3@musicianhub.com / Music123!
echo    demo4@musicianhub.com / Music123!
echo    demo5@musicianhub.com / Music123!
echo.
echo 🎵 NEW COMMUNITY FEATURES:
echo    ✓ Admin-only member approval system
echo    ✓ Primary members (can post)
echo    ✓ Secondary members (can view only)
echo    ✓ Join requests with notifications
echo    ✓ Member status management
echo.
echo ⚠️  IMPORTANT:
echo    • All devices must be on SAME WiFi network
echo    • Keep this window open
echo    • Press Ctrl+C to stop server
echo ========================================================
echo.
echo Starting Flask server...
echo.

REM Change to script directory
cd /d "%~dp0"

REM Run the Flask application
python app.py

if errorlevel 1 (
    echo.
    echo ERROR: Failed to start server!
    echo Possible issues:
    echo 1. Port 5000 is already in use
    echo 2. Database file is corrupted
    echo.
    echo Try deleting musicianhub.db file and restarting.
    echo.
    pause
)

pause