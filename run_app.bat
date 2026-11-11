@echo off
setlocal
cd /d "%~dp0"
title Secure File Sharing App

echo === Secure File Sharing App ===
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher "py" was not found. Install Python 3 and try again.
  goto failed
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  py -m venv .venv
  if errorlevel 1 goto failed
)

call ".venv\Scripts\activate.bat"
echo Installing required packages...
python -m pip install -r requirements.txt
if errorlevel 1 goto failed

if not exist ".flask_secret_key" (
  echo Creating a local secret key...
  python -c "import secrets; print(secrets.token_hex(32))" > ".flask_secret_key"
  if errorlevel 1 goto failed
)
set /p FLASK_SECRET_KEY=<".flask_secret_key"
if "%FLASK_SECRET_KEY%"=="" (
  echo Could not read the local secret key.
  goto failed
)

echo Initializing database...
flask --app app init-db
if errorlevel 1 goto failed

echo Starting app on your Wi-Fi network at port 5000
flask --app app run --host=0.0.0.0 --port=5000
goto finished

:failed
echo.
echo Setup did not complete. Check the message above and try again.
pause
:finished
endlocal

