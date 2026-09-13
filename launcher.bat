@echo off
REM BlackRoute-Web Windows Launcher
setlocal

cd /d "%~dp0"

echo ==================================================
echo      CYBERNEST LABS: BLACKROUTE-WEB v1.0
echo ==================================================
echo [INFO] Verifying Python installation...

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python 3 is not installed or not in PATH.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo [INFO] Creating Python virtual environment...
    python -m venv .venv
)

call .venv\Scripts\activate.bat

echo [INFO] Verifying requirements...
python -c "import fastapi, uvicorn, jinja2, httpx, fpdf" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing required dependencies...
    pip install -q -r requirements.txt
)

echo [INFO] Launching BlackRoute-Web...
python blackroute_web.py

pause
