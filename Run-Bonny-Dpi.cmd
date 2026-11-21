@echo off
setlocal
set "APP=%~dp0src\Bonny.Dpi\bin\Release\net10.0-windows\win-x64\publish\Bonny.Dpi.exe"
if not exist "%APP%" (
  echo Bonny DPI is not built yet. Run Build-Bonny.cmd first.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -Command "Start-Process -FilePath '%APP%' -WorkingDirectory '%~dp0src\Bonny.Dpi\bin\Release\net10.0-windows\win-x64\publish' -Verb RunAs"
