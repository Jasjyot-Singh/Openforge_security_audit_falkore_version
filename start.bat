@echo off
REM Shadowprint One-Click Launcher for Windows
REM Hackathon Track 01: Agents That Act on Connected Data
REM Co-builders: Gaurang Udgirkar & Jasjyot Singh

echo ===============================================================================
echo   SHADOWPRINT v2.0.0 -- Model Context Protocol Security Auditor
echo   Hackathon Track 01: Agents That Act on Connected Data
echo   Co-Builders: Gaurang Udgirkar and Jasjyot Singh
echo ===============================================================================
echo.

set PYCMD=python
where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    where py >nul 2>nul
    if %ERRORLEVEL% EQU 0 (
        set PYCMD=py -3
    ) else (
        echo [ERROR] Python is not installed or not in PATH!
        echo Please install Python 3.10+ from https://www.python.org/
        pause
        exit /b 1
    )
)

%PYCMD% start.py %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [NOTE] If dependencies are missing, run: %PYCMD% -m pip install -r requirements.txt
    pause
)
