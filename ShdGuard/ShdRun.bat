@echo off
setlocal
title ShdGuard
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python 3.10 or newer is required. Install it from python.org and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
python -m pip install --quiet --disable-pip-version-check -r ShdRequirements.txt
if errorlevel 1 (
  echo Dependency install failed. Check your internet connection and run again.
  pause
  exit /b 1
)
net session >nul 2>nul
if errorlevel 1 echo NOTE: not running as Administrator. Failed-logon monitoring ^(Event 4625^) is disabled.
python ShdGuard.py %*
