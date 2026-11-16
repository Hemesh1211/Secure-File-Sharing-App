@echo off
setlocal
cd /d "%~dp0"
title SecureShare // Encrypted File Sharing App

echo ========================================================
echo   SECURESHARE :: AES-256-GCM ENCRYPTED FILE WORKSPACE
echo ========================================================
where py >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python launcher "py" was not found. Install Python 3 and try again.
  goto failed
)

if not exist ".venv\Scripts\python.exe" (
  echo [INIT] Creating isolated Python virtual environment...
  py -m venv .venv
  if errorlevel 1 goto failed
)

call ".venv\Scripts\activate.bat"
echo [DEPS] Installing / verifying dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 goto failed

if not exist ".flask_secret_key" (
  echo [KEYS] Generating 256-bit local master secret key...
  python -c "import secrets; print(secrets.token_hex(32))" > ".flask_secret_key"
  if errorlevel 1 goto failed
)
set /p FLASK_SECRET_KEY=<".flask_secret_key"
if "%FLASK_SECRET_KEY%"=="" (
  echo [ERROR] Could not read the local secret key.
  goto failed
)
set VAULT_MASTER_KEY=%FLASK_SECRET_KEY%

echo [DB] Initializing and migrating SQLite schema...
flask --app app init-db
if errorlevel 1 goto failed

echo [ONLINE] Launching SecureShare at http://127.0.0.1:5000 (and LAN port 5000)
flask --app app run --host=0.0.0.0 --port=5000 --with-threads
goto finished

:failed
echo.
echo [ABORT] Setup did not complete. Check the message above and try again.
pause
:finished
endlocal
