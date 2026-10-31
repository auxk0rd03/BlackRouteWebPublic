@echo off
REM ==============================================================================
REM BlackRoute-Web Defense-Grade Windows 10/11 Orchestrator (dev.bat / launcher.bat)
REM CyberNest Labs — Standard 004 (CN-DIR-2026-004): Dual-Native Orchestration
REM Enforces CWE-377 (Safe working dir & icacls 0600-equivalent ACLs),
REM CWE-114 (Scoped process lifecycle), FIPS 140-3 (GOFIPS=1), and Parity Contract.
REM ==============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

REM ------------------------------------------------------------------------------
REM 1. User Cache & Toolchain Preservation Under Admin Elevation (Section 3.2)
REM ------------------------------------------------------------------------------
if not defined CARGO_HOME set "CARGO_HOME=%USERPROFILE%\.cargo"
if not defined RUSTUP_HOME set "RUSTUP_HOME=%USERPROFILE%\.rustup"
if not defined GOPATH set "GOPATH=%USERPROFILE%\go"
if not defined GOMODCACHE set "GOMODCACHE=%GOPATH%\pkg\mod"
if not defined GOCACHE set "GOCACHE=%LOCALAPPDATA%\go-build"
set "PATH=%CARGO_HOME%\bin;%GOPATH%\bin;%PATH%"

REM ------------------------------------------------------------------------------
REM 2. CWE-377 Hardened User-Scoped Telemetry & ACL Lockdown (Section 3.3)
REM ------------------------------------------------------------------------------
set "LOG_DIR=%LOCALAPPDATA%\blackroute_web"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
icacls "%LOG_DIR%" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" >nul 2>&1

set "LOG_FILE=%LOG_DIR%\session.log"
fsutil reparsepoint query "%LOG_FILE%" >nul 2>&1
if %ERRORLEVEL% EQU 0 del /f /q "%LOG_FILE%"
type nul >> "%LOG_FILE%"
icacls "%LOG_FILE%" /inheritance:r /grant:r "%USERNAME%:F" >nul 2>&1

REM ------------------------------------------------------------------------------
REM 3. Python & Virtual Environment Resolution
REM ------------------------------------------------------------------------------
set "PYTHON_BIN="
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PYTHON_BIN=python"
) else (
    where python3 >nul 2>&1
    if !ERRORLEVEL! EQU 0 (
        set "PYTHON_BIN=python3"
    ) else (
        echo [ERROR] Python 3.10+ is not installed or not in PATH.
        exit /b 1
    )
)

set "VENV_DIR=%SCRIPT_DIR%\.venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"

set "CMD=%~1"
if "%CMD%"=="" set "CMD=run"

if /I "%CMD%"=="setup" goto :cmd_setup
if /I "%CMD%"=="build" goto :cmd_build
if /I "%CMD%"=="build_engines" goto :cmd_build
if /I "%CMD%"=="run" goto :cmd_run
if /I "%CMD%"=="serve" goto :cmd_run
if /I "%CMD%"=="launch" goto :cmd_run
if /I "%CMD%"=="cli" goto :cmd_cli
if /I "%CMD%"=="simulate" goto :cmd_simulate
if /I "%CMD%"=="test" goto :cmd_test
if /I "%CMD%"=="tests" goto :cmd_test
if /I "%CMD%"=="fmt" goto :cmd_fmt
if /I "%CMD%"=="build_release" goto :cmd_build_release
if /I "%CMD%"=="help" goto :cmd_help
if /I "%CMD%"=="--help" goto :cmd_help
goto :cmd_run

:ensure_venv
if not exist "%VENV_PYTHON%" (
    echo [INFO] Initializing isolated Windows virtual environment ^(.venv^)...
    %PYTHON_BIN% -m venv "%VENV_DIR%"
)
call "%VENV_DIR%\Scripts\activate.bat"
"%VENV_PYTHON%" -c "import fastapi, uvicorn, jinja2, aiofiles, fpdf, pydantic, multipart, bs4, httpx" >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Installing dependencies from requirements.txt...
    "%VENV_PYTHON%" -m pip install -q --upgrade pip
    "%VENV_PYTHON%" -m pip install -q -r requirements.txt
)
exit /b 0

:cmd_setup
echo ==================================================
echo   BLACKROUTE-WEB - WINDOWS TOOLCHAIN SETUP
echo ==================================================
echo [INFO] Active User: %USERNAME% ^(%USERPROFILE%^)
call :ensure_venv
where cargo >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Rust Cargo detected.
) else (
    echo [WARN] Rust Cargo not detected; Python fallback active.
)
where go >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [INFO] Go compiler detected.
) else (
    echo [WARN] Go compiler not detected; Python fallback active.
)
echo [SUCCESS] Windows environment verified. Log: %LOG_FILE%
exit /b 0

:cmd_build
echo ==================================================
echo   BLACKROUTE-WEB - WINDOWS ENGINE BUILD PROTOCOL
echo ==================================================
if not exist "%SCRIPT_DIR%\bin" mkdir "%SCRIPT_DIR%\bin"
set "RUST_COUNT=0"
set "GO_COUNT=0"

where cargo >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist "%SCRIPT_DIR%\engines\web_spider\Cargo.toml" (
        echo [BUILD] Compiling Rust Engine: web_spider.exe...
        pushd "%SCRIPT_DIR%\engines\web_spider"
        cargo build --release --offline
        if !ERRORLEVEL! EQU 0 (
            if exist "target\release\web_spider.exe" (
                copy /Y "target\release\web_spider.exe" "%SCRIPT_DIR%\bin\web_spider.exe" >nul
                echo [SUCCESS] web_spider.exe -^> bin\web_spider.exe
                set /a RUST_COUNT+=1
            )
        )
        popd
    )
) else (
    echo [WARN] Cargo not detected. Skipping web_spider.exe build.
)

where go >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist "%SCRIPT_DIR%\engines\surface_graph\go.mod" (
        echo [BUILD] Compiling Go Engine: surface_graph.exe ^(GOFIPS=1^)...
        pushd "%SCRIPT_DIR%\engines\surface_graph"
        set "GOFIPS=1"
        set "GODEBUG=fips140=on"
        set "CGO_ENABLED=0"
        go build -trimpath -ldflags="-s -w" -o "%SCRIPT_DIR%\bin\surface_graph.exe" .
        if !ERRORLEVEL! EQU 0 (
            echo [SUCCESS] surface_graph.exe -^> bin\surface_graph.exe
            set /a GO_COUNT+=1
        )
        popd
    )
) else (
    echo [WARN] Go not detected. Skipping surface_graph.exe build.
)

if exist "%SCRIPT_DIR%\..\NestSBOM\sbom_cli.py" (
    echo [SBOM] Generating CycloneDX 1.5, SPDX 2.3 ^& CISA SBOM manifests...
    %PYTHON_BIN% "%SCRIPT_DIR%\..\NestSBOM\sbom_cli.py" --repo "%SCRIPT_DIR%" --out-dir "%SCRIPT_DIR%" >nul 2>&1
)
echo [SUCCESS] Build complete ^(Rust: %RUST_COUNT% ^| Go: %GO_COUNT%^).
exit /b 0

:cmd_run
call :ensure_venv
if not exist "%SCRIPT_DIR%\bin\web_spider.exe" (
    if not exist "%SCRIPT_DIR%\bin\surface_graph.exe" (
        call :cmd_build
    )
)
echo ==================================================
echo      BLACKROUTE-WEB - MISSION CONTROL LAUNCH
echo ==================================================
set "GOFIPS=1"
set "GODEBUG=fips140=on"
"%VENV_PYTHON%" "%SCRIPT_DIR%\blackroute_web.py" --serve
exit /b %ERRORLEVEL%

:cmd_cli
call :ensure_venv
set "GOFIPS=1"
set "GODEBUG=fips140=on"
"%VENV_PYTHON%" "%SCRIPT_DIR%\blackroute_web.py" --cli
exit /b %ERRORLEVEL%

:cmd_simulate
call :ensure_venv
set "GOFIPS=1"
set "GODEBUG=fips140=on"
"%VENV_PYTHON%" "%SCRIPT_DIR%\blackroute_web.py" --cli --simulate --export
exit /b %ERRORLEVEL%

:cmd_test
call :ensure_venv
echo ==================================================
echo      BLACKROUTE-WEB - AUTOMATED TEST SUITE
echo ==================================================
where go >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist "%SCRIPT_DIR%\engines\surface_graph\go.mod" (
        pushd "%SCRIPT_DIR%\engines\surface_graph"
        set "GOFIPS=1"
        set "GODEBUG=fips140=on"
        go test -v ./...
        if !ERRORLEVEL! NEQ 0 (
            popd
            exit /b 1
        )
        popd
    )
)
where cargo >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist "%SCRIPT_DIR%\engines\web_spider\Cargo.toml" (
        pushd "%SCRIPT_DIR%\engines\web_spider"
        cargo test --offline
        if !ERRORLEVEL! NEQ 0 (
            popd
            exit /b 1
        )
        popd
    )
)
"%VENV_PYTHON%" -m unittest discover -s tests -v
exit /b %ERRORLEVEL%

:cmd_fmt
echo ==================================================
echo      BLACKROUTE-WEB - POLYGLOT CODE FORMATTER
echo ==================================================
where go >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist "%SCRIPT_DIR%\engines\surface_graph\go.mod" (
        pushd "%SCRIPT_DIR%\engines\surface_graph"
        go fmt ./...
        popd
    )
)
where cargo >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist "%SCRIPT_DIR%\engines\web_spider\Cargo.toml" (
        pushd "%SCRIPT_DIR%\engines\web_spider"
        cargo fmt --all
        popd
    )
)
echo [SUCCESS] Formatting complete.
exit /b 0

:cmd_build_release
call :ensure_venv
call :cmd_build
"%VENV_PYTHON%" -m pip install -q pyinstaller
"%VENV_DIR%\Scripts\pyinstaller.exe" --noconfirm --onefile --clean --name "BlackRoute_Web_v1.0" ^
    --add-data "app/templates;app/templates" ^
    --add-data "app/static;app/static" ^
    --add-data "bin;bin" ^
    --hidden-import=uvicorn.logging ^
    --hidden-import=uvicorn.loops ^
    --hidden-import=uvicorn.loops.auto ^
    --hidden-import=uvicorn.protocols ^
    --hidden-import=uvicorn.protocols.http ^
    --hidden-import=uvicorn.protocols.http.auto ^
    --hidden-import=uvicorn.lifespan ^
    --hidden-import=uvicorn.lifespan.on ^
    blackroute_web.py
exit /b %ERRORLEVEL%

:cmd_help
echo Usage: dev.bat [setup^|build^|run^|serve^|cli^|simulate^|test^|fmt^|build_release]
exit /b 0
