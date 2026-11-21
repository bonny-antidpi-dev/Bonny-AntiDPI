@echo off
setlocal
chcp 65001 >nul
set "BONNY_ROOT=%~dp0"
set "DOTNET=dotnet"
if exist "%~dp0.tools\dotnet\dotnet.exe" set "DOTNET=%~dp0.tools\dotnet\dotnet.exe"
powershell.exe -NoProfile -Command "$root = [IO.Path]::GetFullPath($env:BONNY_ROOT); $running = Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('Bonny.Dpi.Cli.exe', 'Bonny.Dpi.exe') -and $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) }; if ($running) { $running | ForEach-Object { Write-Output ('PID {0}: {1}' -f $_.ProcessId, $_.ExecutablePath) }; exit 2 }"
if errorlevel 2 goto bonny_running
if errorlevel 1 goto process_check_failed
"%DOTNET%" publish "%~dp0src\Bonny.Dpi\Bonny.Dpi.csproj" --configuration Release --self-contained true
if errorlevel 1 goto build_failed
"%DOTNET%" publish "%~dp0src\Bonny.Dpi.Cli\Bonny.Dpi.Cli.csproj" --configuration Release --self-contained true
if errorlevel 1 goto build_failed
exit /b 0

:bonny_running
echo.
echo Сборка не запущена: Bonny сейчас открыт и блокирует файлы приложения.
echo Закрой окно Bonny или нажми Ctrl+C в работающей консоли, затем запусти Build-Bonny.cmd ещё раз.
pause
exit /b 2

:process_check_failed
echo Не удалось проверить запущенные процессы Bonny. Сборка отменена, чтобы не перезаписывать используемые файлы.
pause
exit /b 1

:build_failed
set "BUILD_RESULT=%ERRORLEVEL%"
echo Bonny build failed with exit code %BUILD_RESULT%.
pause
exit /b %BUILD_RESULT%
