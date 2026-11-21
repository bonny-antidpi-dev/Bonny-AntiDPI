using Bonny.Dpi;
using System.Diagnostics;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;

return await BonnyCli.RunAsync(args);

internal static class BonnyCli
{
    public static async Task<int> RunAsync(string[] args)
    {
        var command = args.Length == 0 ? "menu" : args[0].ToLowerInvariant();
        if (args.Length > 1)
        {
            Console.Error.WriteLine("Команда принимает только один аргумент.");
            PrintHelp();
            return 2;
        }

        return command switch
        {
            "menu" => await RunMenuAsync(),
            "help" or "-h" or "--help" or "/?" => PrintHelpAndReturn(),
            "check" => CheckReadiness(),
            "setup" => await InstallWinDivertAsync(),
            "start" => await StartAsync(),
            "update-media-sites" => await BlockedMediaListUpdater.UpdateAsync(DomainPolicy.FindListPath(AppContext.BaseDirectory)),
            "germany" => GermanyTunnel.RunMenu(),
            "germany-connect" => GermanyTunnel.Connect(),
            "germany-reconnect" => GermanyTunnel.Reconnect(),
            "germany-disconnect" => GermanyTunnel.Disconnect(),
            "germany-status" => GermanyTunnel.Status(),
            "diagnose" => await RunNetworkDiagnosticsAsync(),
            "adblock" => OpenFirefoxAdBlockPage(),
            _ => UnknownCommand(command)
        };
    }

    private static async Task<int> RunMenuAsync()
    {
        ShowStartupAnimation();

        while (true)
        {
            ClearMenuScreen();
            Console.WriteLine();
            Console.WriteLine("======================================");
            Console.WriteLine("             Bonny — меню CMD");
            Console.WriteLine("======================================");
            Console.WriteLine("  1. Запустить обход");
            Console.WriteLine("  2. Автоустановка компонентов");
            Console.WriteLine("  3. Проверить готовность");
            Console.WriteLine("  4. Открыть список доменов");
            Console.WriteLine("  5. Справка");
            Console.WriteLine("  6. Немецкий IP через WireGuard VPS");
            Console.WriteLine("  7. Диагностика сети для семи сервисов");
            Console.WriteLine("  8. Блокировщик рекламы для Firefox");
            Console.WriteLine("  9. Обновить список заблокированных СМИ");
            Console.WriteLine("  0. Выход");
            Console.Write("Выбор: ");

            var selection = Console.ReadLine()?.Trim();
            switch (selection)
            {
                case "1":
                    StartFromMenu();
                    break;
                case "2":
                    _ = await InstallWinDivertAsync();
                    WaitForMenu();
                    break;
                case "3":
                    _ = CheckReadiness();
                    WaitForMenu();
                    break;
                case "4":
                    OpenDomainList();
                    break;
                case "5":
                    PrintHelp();
                    WaitForMenu();
                    break;
                case "6":
                    _ = GermanyTunnel.RunMenu();
                    break;
                case "7":
                    _ = await RunNetworkDiagnosticsAsync();
                    WaitForMenu();
                    break;
                case "8":
                    _ = OpenFirefoxAdBlockPage();
                    WaitForMenu();
                    break;
                case "9":
                    _ = await BlockedMediaListUpdater.UpdateAsync(DomainPolicy.FindListPath(AppContext.BaseDirectory));
                    WaitForMenu();
                    break;
                case "0":
                case null:
                    return 0;
                default:
                    Console.WriteLine("Выберите пункт 1, 2, 3, 4, 5, 6, 7, 8, 9 или 0.");
                    break;
            }
        }
    }

    private static void ClearMenuScreen()
    {
        if (Console.IsOutputRedirected)
            return;

        try
        {
            Console.Clear();
        }
        catch (IOException)
        {
            // Keep the menu usable in terminals that do not support screen clearing.
        }
    }

    private static void StartFromMenu()
    {
        var executablePath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            Console.WriteLine("Не удалось определить путь к Bonny.");
            WaitForMenu();
            return;
        }

        try
        {
            var startInfo = new ProcessStartInfo(executablePath, "start")
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory
            };
            using var process = Process.Start(startInfo);
            process?.WaitForExit();
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            Console.WriteLine("Запрос прав администратора отменён.");
            WaitForMenu();
        }
        catch (Exception ex)
        {
            Console.WriteLine("Не удалось запустить Bonny: " + ex.GetBaseException().Message);
            WaitForMenu();
        }
    }

    private static void OpenDomainList()
    {
        var domainsPath = DomainPolicy.FindListPath(AppContext.BaseDirectory);
        if (!File.Exists(domainsPath))
        {
            Console.WriteLine("Не найден файл: " + domainsPath);
            WaitForMenu();
            return;
        }

        try
        {
            _ = Process.Start(new ProcessStartInfo(domainsPath) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Console.WriteLine("Не удалось открыть список доменов: " + ex.GetBaseException().Message);
            WaitForMenu();
        }
    }

    private static void WaitForMenu()
    {
        Console.WriteLine();
        Console.Write("Нажмите Enter, чтобы вернуться в меню...");
        _ = Console.ReadLine();
    }

    private static void ShowStartupAnimation()
    {
        if (Console.IsOutputRedirected)
            return;

        try
        {
            Console.CursorVisible = false;
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine(@"       ____                    ");
            Console.WriteLine(@"      | __ )  ___  _ __  _ __  _   ");
            Console.WriteLine(@"      |  _ \ / _ \| '_ \| '_ \| |  ");
            Console.WriteLine(@"      | |_) | (_) | | | | | | | |__");
            Console.WriteLine(@"      |____/ \___/|_| |_|_| |_|\___|");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("             Bonny DPI");
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("       Подготавливаем меню");
            Console.WriteLine();

            const int barWidth = 28;
            for (var frame = 0; frame <= barWidth; frame++)
            {
                var percent = frame * 100 / barWidth;
                Console.Write("       [");
                for (var cell = 0; cell < barWidth; cell++)
                {
                    Console.ForegroundColor = cell < frame ? ConsoleColor.Cyan : ConsoleColor.DarkGray;
                    Console.Write(cell < frame ? '#' : '-');
                }
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"] {percent,3}%\r");
                Thread.Sleep(35);
            }
            Console.WriteLine();
            Thread.Sleep(180);
        }
        catch (IOException)
        {
            // Animation is decorative; keep the menu available if the terminal has limited support.
        }
        finally
        {
            try
            {
                Console.ResetColor();
                Console.CursorVisible = true;
                Console.Clear();
            }
            catch (IOException)
            {
                // Keep startup working if console control is unavailable.
            }
        }
    }

    private static async Task<int> InstallWinDivertAsync()
    {
        const string archiveUrl = "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip";
        const string expectedArchiveSha256 = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15";
        const string expectedDllSha256 = "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2";
        const string expectedDriverSha256 = "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2";
        const int maximumArchiveBytes = 5 * 1024 * 1024;

        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
        {
            Console.WriteLine("Автоустановка поддерживается только на Windows x64.");
            return 1;
        }

        var nativeDirectory = Path.Combine(AppContext.BaseDirectory, "native");
        var destinationDll = Path.Combine(nativeDirectory, "WinDivert.dll");
        var destinationDriver = Path.Combine(nativeDirectory, "WinDivert64.sys");
        if (await FileMatchesSha256Async(destinationDll, expectedDllSha256) &&
            await FileMatchesSha256Async(destinationDriver, expectedDriverSha256))
        {
            Console.WriteLine("Проверенные компоненты WinDivert уже установлены.");
            return 0;
        }

        var stagingDirectory = Path.Combine(Path.GetTempPath(), "Bonny-WinDivert-" + Guid.NewGuid().ToString("N"));
        try
        {
            Console.WriteLine("Источник: официальный релиз WinDivert 2.2.2-A на GitHub.");
            Console.WriteLine("Скачивается архив и проверяются контрольные суммы. Защита Windows остаётся включена.");

            using var httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
            using var response = await httpClient.GetAsync(archiveUrl, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength is > maximumArchiveBytes)
                throw new InvalidDataException("Размер архива превышает допустимый предел.");

            await using var source = await response.Content.ReadAsStreamAsync();
            using var archiveBuffer = new MemoryStream();
            var buffer = new byte[32 * 1024];
            while (true)
            {
                var read = await source.ReadAsync(buffer);
                if (read == 0)
                    break;
                if (archiveBuffer.Length + read > maximumArchiveBytes)
                    throw new InvalidDataException("Размер архива превышает допустимый предел.");
                await archiveBuffer.WriteAsync(buffer.AsMemory(0, read));
            }

            var archiveHash = Convert.ToHexString(SHA256.HashData(archiveBuffer.GetBuffer().AsSpan(0, checked((int)archiveBuffer.Length)))).ToLowerInvariant();
            if (!archiveHash.Equals(expectedArchiveSha256, StringComparison.Ordinal))
                throw new InvalidDataException("Контрольная сумма архива не совпала; файлы не установлены.");

            archiveBuffer.Position = 0;
            using var archive = new ZipArchive(archiveBuffer, ZipArchiveMode.Read, leaveOpen: true);
            var dllEntry = FindArchiveEntry(archive, "WinDivert.dll");
            var driverEntry = FindArchiveEntry(archive, "WinDivert64.sys");
            Directory.CreateDirectory(stagingDirectory);
            var stagedDll = Path.Combine(stagingDirectory, "WinDivert.dll");
            var stagedDriver = Path.Combine(stagingDirectory, "WinDivert64.sys");
            await ExtractVerifiedEntryAsync(dllEntry, stagedDll, expectedDllSha256);
            await ExtractVerifiedEntryAsync(driverEntry, stagedDriver, expectedDriverSha256);

            Directory.CreateDirectory(nativeDirectory);
            File.Copy(stagedDll, destinationDll, overwrite: true);
            File.Copy(stagedDriver, destinationDriver, overwrite: true);

            Console.WriteLine("WinDivert.dll и WinDivert64.sys установлены рядом с Bonny.");
            Console.WriteLine("Драйвер загрузится при запуске обхода с правами администратора.");
            return 0;
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException or UnauthorizedAccessException or InvalidDataException)
        {
            Console.WriteLine("Автоустановка не выполнена: " + ex.GetBaseException().Message);
            Console.WriteLine("Если антивирус заблокировал архив или файл, не отключайте защиту и не обходите блокировку.");
            return 1;
        }
        finally
        {
            try
            {
                if (Directory.Exists(stagingDirectory))
                    Directory.Delete(stagingDirectory, recursive: true);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The operating system or security software may have removed part of the staging folder already.
            }
        }
    }

    private static ZipArchiveEntry FindArchiveEntry(ZipArchive archive, string fileName)
    {
        var entry = archive.Entries.FirstOrDefault(item =>
        {
            var normalizedName = item.FullName.Replace('\\', '/');
            return normalizedName.Equals("x64/" + fileName, StringComparison.OrdinalIgnoreCase) ||
                   normalizedName.EndsWith("/x64/" + fileName, StringComparison.OrdinalIgnoreCase);
        });
        return entry ?? throw new InvalidDataException($"В архиве не найден x64/{fileName}.");
    }

    private static async Task ExtractVerifiedEntryAsync(ZipArchiveEntry entry, string destination, string expectedSha256)
    {
        if (entry.Length <= 0 || entry.Length > 4 * 1024 * 1024)
            throw new InvalidDataException($"Недопустимый размер файла {entry.Name}.");

        await using (var input = entry.Open())
        await using (var output = new FileStream(destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            await input.CopyToAsync(output);

        if (!await FileMatchesSha256Async(destination, expectedSha256))
            throw new InvalidDataException($"Контрольная сумма {entry.Name} не совпала.");
    }

    private static async Task<bool> FileMatchesSha256Async(string path, string expectedSha256)
    {
        if (!File.Exists(path))
            return false;

        await using var file = File.OpenRead(path);
        var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(file)).ToLowerInvariant();
        return actualHash.Equals(expectedSha256, StringComparison.Ordinal);
    }

    private static int CheckReadiness()
    {
        var baseDirectory = AppContext.BaseDirectory;
        var domainsPath = DomainPolicy.FindListPath(baseDirectory);
        var nativeDirectory = Path.Combine(baseDirectory, "native");
        var dllPath = Path.Combine(nativeDirectory, "WinDivert.dll");
        var driverPath = Path.Combine(nativeDirectory, "WinDivert64.sys");
        var ready = true;

        Console.WriteLine("Проверка Bonny DPI");
        Console.WriteLine($"Папка запуска: {baseDirectory}");

        try
        {
            _ = DomainPolicy.Load(domainsPath);
            Console.WriteLine("Список domains.txt: OK");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            Console.WriteLine("Список domains.txt: ОШИБКА — " + ex.Message);
            ready = false;
        }

        var dllExists = File.Exists(dllPath);
        var driverExists = File.Exists(driverPath);
        Console.WriteLine($"WinDivert.dll: {(dllExists ? "OK" : "не найден")}");
        Console.WriteLine($"WinDivert64.sys: {(driverExists ? "OK" : "не найден")}");
        if (!dllExists || !driverExists)
        {
            Console.WriteLine("Перехват сейчас недоступен. См. native\\README.md; не отключайте защиту Windows.");
            ready = false;
        }

        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
        {
            Console.WriteLine("Запуск движка поддерживается только на Windows x64.");
            ready = false;
        }

        Console.WriteLine(ready
            ? "Готово к запуску. Для start потребуются права администратора."
            : "Проверка не пройдена.");
        return ready ? 0 : 1;
    }

    private static async Task<int> StartAsync()
    {
        ShowStartupAnimation();
        Console.WriteLine("Проверяю компоненты перед запуском.");
        if (await InstallWinDivertAsync() != 0 || CheckReadiness() != 0)
            return 1;

        var domainsPath = DomainPolicy.FindListPath(AppContext.BaseDirectory);
        WinDivertDpiEngine? engine = null;
        BonnyTrayController? tray = null;
        using var stopRequested = new ManualResetEvent(false);
        using var engineStopped = new ManualResetEvent(false);

        ConsoleCancelEventHandler cancelHandler = (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            stopRequested.Set();
        };
        Console.CancelKeyPress += cancelHandler;

        try
        {
            var policy = DomainPolicy.Load(domainsPath);
            engine = new WinDivertDpiEngine(policy);
            engine.Log += BonnyConsole.WriteEngineLog;
            engine.Stopped += _ => engineStopped.Set();
            engine.Start();
            tray = new BonnyTrayController(() => stopRequested.Set());
            BonnyConsole.WriteRunningPanel();

            await Task.Run(() => WaitHandle.WaitAny([stopRequested, engineStopped]));
            return stopRequested.WaitOne(0) ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Не удалось запустить Bonny: " + ex.GetBaseException().Message);
            return 1;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
            tray?.ShowConsole();
            engine?.Dispose();
            tray?.Dispose();
        }
    }

    private static int PrintHelpAndReturn()
    {
        PrintHelp();
        return 0;
    }

    private static void PrintHelp()
    {
        Console.WriteLine("Bonny DPI — управление из командной строки");
        Console.WriteLine();
        Console.WriteLine("Использование: Run-Bonny.cmd [menu|start|setup|check|diagnose|adblock|update-media-sites|germany|germany-connect|germany-reconnect|germany-disconnect|germany-status|help]");
        Console.WriteLine("  menu   Открыть интерактивное меню CMD.");
        Console.WriteLine("  start  Run-Bonny.cmd запросит права администратора, проверит компоненты и запустит обработчик.");
        Console.WriteLine("  setup  Скачать и проверить официальные файлы WinDivert.");
        Console.WriteLine("  check  Проверить список доменов и файлы WinDivert.");
        Console.WriteLine("  diagnose Проверить DNS, TCP/443 и TLS для семи сервисов.");
        Console.WriteLine("  adblock  Открыть страницу uBlock Origin для Firefox.");
        Console.WriteLine("  update-media-sites Обновить домены из списка заблокированных СМИ в Википедии.");
        Console.WriteLine("  germany Открыть настройки немецкого WireGuard-туннеля.");
        Console.WriteLine("  germany-reconnect Перезапустить выбранный профиль WireGuard.");
        Console.WriteLine("  help   Показать эту справку.");
        Console.WriteLine();
        Console.WriteLine("Для выхода из работающего обработчика нажмите Ctrl+C.");
    }

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"Неизвестная команда: {command}");
        PrintHelp();
        return 2;
    }

    private static int OpenFirefoxAdBlockPage()
    {
        const string addOnUrl = "https://addons.mozilla.org/firefox/addon/ublock-origin/";
        try
        {
            _ = Process.Start(new ProcessStartInfo(addOnUrl) { UseShellExecute = true });
            Console.WriteLine("Открыл страницу uBlock Origin. Установи расширение в Firefox, чтобы фильтровать рекламу в браузере.");
            Console.WriteLine("Bonny не меняет настройки Firefox и не фильтрует содержимое браузера самостоятельно.");
            return 0;
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Console.Error.WriteLine("Не удалось открыть страницу расширения: " + ex.GetBaseException().Message);
            Console.WriteLine("Открой в Firefox: " + addOnUrl);
            return 1;
        }
    }

    private static async Task<int> RunNetworkDiagnosticsAsync()
    {
        Console.WriteLine("Проверяю DNS, TCP/443 и TLS до основных доменов сервисов.");
        Console.WriteLine("Проверяю Discord, Telegram, YouTube, Roblox, TikTok, SoundCloud и Spotify.");
        Console.WriteLine("Проверка использует текущие системные маршруты, включая активный WireGuard-туннель.");
        IReadOnlyList<NetworkDiagnosticResult> results;
        try
        {
            results = await NetworkDiagnostics.RunAsync();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Диагностика прервана: " + ex.GetBaseException().Message);
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine($"{"Сервис",-10} {"DNS",-7} {"TCP/443",-9} {"TLS",-7} {"Маршрут",-7} Домен");
        foreach (var result in results)
        {
            Console.WriteLine($"{result.Service,-10} {Mark(result.DnsOk),-7} {Mark(result.Tcp443Ok),-9} {Mark(result.TlsOk),-7} {result.AddressFamily,-7} {result.Host}");
            if (!string.IsNullOrWhiteSpace(result.Detail))
                Console.WriteLine($"  {result.Detail}");
        }

        Console.WriteLine();
        Console.WriteLine("Это проверка базового HTTPS-доступа. Она не проверяет голос Discord, игровые UDP-соединения или успешность обхода DPI.");
        return results.All(result => result.TlsOk) ? 0 : 1;
    }

    private static string Mark(bool ok) => ok ? "OK" : "FAIL";
}
