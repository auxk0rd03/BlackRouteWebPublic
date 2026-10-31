@echo off
REM ==============================================================================
REM BlackRoute-Web Unified Windows Launcher (launcher.bat -> dev.bat parity)
REM CyberNest Labs — Standard 004 (CN-DIR-2026-004): Dual-Native Orchestration
REM ==============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
call "%~dp0dev.bat" %*
exit /b %ERRORLEVEL%
