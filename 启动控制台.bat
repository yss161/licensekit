@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"
title LicenseKit 授权管理控制台

where python >nul 2>&1
if errorlevel 1 (
    echo.
    echo   [!] Not found: python
    echo       Please install Python 3.8+ and check "Add to PATH".
    echo.
    pause
    exit /b 1
)

python licensekit.py
if errorlevel 1 pause
