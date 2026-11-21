@echo off
setlocal
chcp 65001 >nul
title Bonny CMD
set "PUBLISH_DIR=%~dp0src\Bonny.Dpi.Cli\bin\Release\net10.0-windows\win-x64\publish"
set "APP=%PUBLISH_DIR%\Bonny.Dpi.Cli.exe"
if not exist "%APP%" (
  echo Bonny CMD is not built yet. Run Build-Bonny.cmd first.
  pause
  exit /b 1
)

set "COMMAND=%~1"
if not defined COMMAND set "COMMAND=menu"
if /I "%COMMAND%"=="germany-setup" goto passthrough
if /I "%COMMAND%"=="germany-autostart-enable" goto passthrough
if /I "%COMMAND%"=="germany-autostart-disable" goto passthrough
if not "%~2"=="" goto invalid_arguments
if /I "%COMMAND%"=="menu" goto menu
if /I "%COMMAND%"=="check" goto check_once
if /I "%COMMAND%"=="diagnose" goto diagnose_once
if /I "%COMMAND%"=="setup" goto setup_once
if /I "%COMMAND%"=="help" goto help_once
if /I "%COMMAND%"=="update-media-sites" goto update_media_sites
if /I "%COMMAND%"=="germany" goto germany
if /I "%COMMAND%"=="germany-connect" goto germany_connect
if /I "%COMMAND%"=="germany-reconnect" goto germany_reconnect
if /I "%COMMAND%"=="germany-disconnect" goto germany_disconnect
if /I "%COMMAND%"=="germany-status" goto germany_status
if /I "%COMMAND%"=="start" goto start

echo Unknown command: %COMMAND%
"%APP%" help
exit /b 2

:invalid_arguments
echo Only one command is accepted.
"%APP%" help
exit /b 2

:menu
"%APP%" menu
exit /b %ERRORLEVEL%

:check_once
"%APP%" check
exit /b %ERRORLEVEL%

:diagnose_once
"%APP%" diagnose
exit /b %ERRORLEVEL%

:setup_once
"%APP%" setup
exit /b %ERRORLEVEL%

:help_once
"%APP%" help
exit /b %ERRORLEVEL%

:update_media_sites
"%APP%" update-media-sites
exit /b %ERRORLEVEL%

:germany
"%APP%" germany
exit /b %ERRORLEVEL%

:germany_connect
"%APP%" germany-connect
exit /b %ERRORLEVEL%

:germany_reconnect
"%APP%" germany-reconnect
exit /b %ERRORLEVEL%

:germany_disconnect
"%APP%" germany-disconnect
exit /b %ERRORLEVEL%

:germany_status
"%APP%" germany-status
exit /b %ERRORLEVEL%

:passthrough
"%APP%" %*
exit /b %ERRORLEVEL%

:start
set "BONNY_APP=%APP%"
set "BONNY_WORKDIR=%PUBLISH_DIR%"
powershell.exe -NoProfile -Command "$isAdmin = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); if ($isAdmin) { & $env:BONNY_APP start; exit $LASTEXITCODE }; try { $p = Start-Process -FilePath $env:BONNY_APP -ArgumentList 'start' -WorkingDirectory $env:BONNY_WORKDIR -Verb RunAs -Wait -PassThru; exit $p.ExitCode } catch { if ($_.Exception.NativeErrorCode -eq 1223) { Write-Host 'Запуск отменён пользователем.'; exit 1223 }; throw }"
exit /b %ERRORLEVEL%
