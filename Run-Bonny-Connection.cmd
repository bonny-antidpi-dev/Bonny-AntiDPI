@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0Bonny-Connection.ps1"
if errorlevel 1 pause
