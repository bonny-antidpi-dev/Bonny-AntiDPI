using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

internal static class GermanyTunnel
{
    private const string DefaultProfileName = "BonnyGermany";
    private static readonly string ConfigDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Bonny");
    private static readonly string ActiveProfilePath = Path.Combine(ConfigDirectory, "SelectedWireGuardProfile.txt");

    public static int RunMenu()
    {
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("======================================");
            Console.WriteLine("       Немецкий IP — WireGuard");
            Console.WriteLine("======================================");
            Console.WriteLine("  1. Импортировать конфиг VPS");
            Console.WriteLine("  2. Выбрать профиль");
            Console.WriteLine("  3. Подключиться");
            Console.WriteLine("  4. Переподключиться");
            Console.WriteLine("  5. Отключиться");
            Console.WriteLine("  6. Проверить состояние");
            Console.WriteLine("  0. Назад");
            Console.Write("Выбор: ");

            switch (Console.ReadLine()?.Trim())
            {
                case "1":
                    ImportConfig();
                    break;
                case "2":
                    SelectProfile();
                    break;
                case "3":
                    _ = Connect();
                    break;
                case "4":
                    _ = Reconnect();
                    break;
                case "5":
                    _ = Disconnect();
                    break;
                case "6":
                    _ = Status();
                    break;
                case "0":
                case null:
                    return 0;
                default:
                    Console.WriteLine("Выберите пункт 1, 2, 3, 4, 5, 6 или 0.");
                    break;
            }
        }
    }

    public static int Connect()
    {
        var profileName = GetActiveProfileName();
        if (profileName is null)
        {
            Console.WriteLine("Сначала импортируйте и выберите профиль WireGuard в меню Германии.");
            return 1;
        }

        var configPath = GetConfigPath(profileName);
        string config;
        try
        {
            config = File.ReadAllText(configPath);
            ValidateConfig(config);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            Console.Error.WriteLine("Профиль WireGuard не подходит: " + ex.GetBaseException().Message);
            return 1;
        }

        var wireGuardPath = FindWireGuard();
        if (wireGuardPath is null)
        {
            Console.WriteLine("Не найден WireGuard для Windows. Установите официальный клиент: https://www.wireguard.com/install/");
            return 1;
        }

        if (!IsAdministrator())
            return RunElevated("germany-connect");

        if (AnyOtherTunnelRunning(profileName))
        {
            Console.WriteLine("Сначала отключите другой профиль Bonny WireGuard.");
            return 1;
        }

        var serviceName = ServiceNameFor(profileName);
        var state = QueryServiceState(profileName);
        if (state == ServiceState.Running)
        {
            Console.WriteLine("Профиль " + profileName + " уже подключён.");
            return 0;
        }

        if (state == ServiceState.NotInstalled)
        {
            var install = RunProcess(wireGuardPath, ["/installtunnelservice", configPath]);
            if (install.ExitCode != 0 && QueryServiceState(profileName) == ServiceState.NotInstalled)
            {
                Console.Error.WriteLine("WireGuard не смог установить туннель.");
                WriteProcessOutput(install.Output);
                return install.ExitCode == 0 ? 1 : install.ExitCode;
            }
        }
        else if (state != ServiceState.Stopped)
        {
            Console.Error.WriteLine("Состояние службы профиля неизвестно. Сначала проверьте его через меню.");
            return 1;
        }

        // Keep the optional tunnel manual before starting any previously installed service.
        var startup = RunSc("config", serviceName, "start=", "demand");
        if (startup.ExitCode != 0)
        {
            Console.Error.WriteLine("Не удалось перевести службу туннеля в ручной режим запуска Windows.");
            WriteProcessOutput(startup.Output);
            return startup.ExitCode;
        }

        if (state == ServiceState.Stopped)
        {
            var start = RunSc("start", serviceName);
            if (start.ExitCode != 0 && QueryServiceState(profileName) != ServiceState.Running)
            {
                Console.Error.WriteLine("Не удалось запустить профиль " + profileName + ".");
                WriteProcessOutput(start.Output);
                return start.ExitCode;
            }
        }

        if (!WaitForState(profileName, ServiceState.Running, TimeSpan.FromSeconds(15)))
        {
            Console.Error.WriteLine("Служба WireGuard не перешла в состояние Running. Проверьте конфиг и UDP-порт VPS.");
            return 1;
        }

        Console.WriteLine("Служба туннеля " + profileName + " запущена.");
        Console.WriteLine("Это ещё не подтверждает handshake или немецкую страну выхода; используйте диагностику сети.");
        return 0;
    }

    public static int Reconnect()
    {
        var profileName = GetActiveProfileName();
        if (profileName is null)
        {
            Console.WriteLine("Сначала импортируйте и выберите профиль WireGuard в меню Германии.");
            return 1;
        }

        var state = QueryServiceState(profileName);
        if (state is ServiceState.NotInstalled or ServiceState.Stopped)
            return Connect();

        if (!IsAdministrator())
            return RunElevated("germany-reconnect");

        if (state != ServiceState.Running)
        {
            Console.WriteLine("Служба профиля ещё запускается или останавливается. Повторите через несколько секунд.");
            return 1;
        }

        var stop = RunSc("stop", ServiceNameFor(profileName));
        if (stop.ExitCode != 0 && QueryServiceState(profileName) != ServiceState.Stopped)
        {
            Console.Error.WriteLine("Не удалось остановить туннель перед повторным подключением.");
            WriteProcessOutput(stop.Output);
            return stop.ExitCode;
        }

        if (!WaitForState(profileName, ServiceState.Stopped, TimeSpan.FromSeconds(15)))
        {
            Console.Error.WriteLine("Служба WireGuard ещё останавливается.");
            return 1;
        }

        Console.WriteLine("Перезапускаю профиль " + profileName + "...");
        return Connect();
    }

    public static int Disconnect()
    {
        var profileName = GetActiveProfileName();
        if (profileName is null)
        {
            Console.WriteLine("Профиль WireGuard отсутствует.");
            return 0;
        }

        var state = QueryServiceState(profileName);
        if (state is ServiceState.NotInstalled or ServiceState.Stopped)
        {
            Console.WriteLine("Профиль " + profileName + " уже отключён.");
            return 0;
        }

        if (!IsAdministrator())
            return RunElevated("germany-disconnect");

        var stop = RunSc("stop", ServiceNameFor(profileName));
        if (stop.ExitCode != 0 && QueryServiceState(profileName) != ServiceState.Stopped)
        {
            Console.Error.WriteLine("Не удалось отключить профиль " + profileName + ".");
            WriteProcessOutput(stop.Output);
            return stop.ExitCode;
        }

        if (!WaitForState(profileName, ServiceState.Stopped, TimeSpan.FromSeconds(15)))
        {
            Console.Error.WriteLine("Служба WireGuard ещё останавливается. Проверьте состояние в меню через несколько секунд.");
            return 1;
        }

        Console.WriteLine("Профиль " + profileName + " отключён.");
        return 0;
    }

    public static int Status()
    {
        var profiles = GetProfileNames();
        if (profiles.Count == 0)
        {
            Console.WriteLine("Профили WireGuard: отсутствуют");
            Console.WriteLine("Сначала импортируйте конфиг VPS через меню Германии.");
            return 0;
        }

        var activeProfile = GetActiveProfileName();
        Console.WriteLine("Профили WireGuard:");
        foreach (var profileName in profiles)
        {
            var marker = string.Equals(profileName, activeProfile, StringComparison.OrdinalIgnoreCase) ? " [выбран]" : string.Empty;
            var state = QueryServiceState(profileName);
            var label = state switch
            {
                ServiceState.Running => "служба работает",
                ServiceState.Stopped => "отключён",
                ServiceState.NotInstalled => "ещё не установлен",
                _ => "состояние неизвестно"
            };
            Console.WriteLine("  " + profileName + marker + ": " + label);
        }
        Console.WriteLine("Статус службы не подтверждает handshake или страну выхода.");
        return 0;
    }

    private static void ImportConfig()
    {
        Console.WriteLine("Укажите путь к клиентскому .conf, созданному на вашем VPS.");
        Console.Write("Файл: ");
        var source = Console.ReadLine()?.Trim().Trim('"');
        if (string.IsNullOrWhiteSpace(source) || !File.Exists(source))
        {
            Console.WriteLine("Файл не найден.");
            return;
        }

        Console.Write("Имя профиля (латиница, цифры, дефис или подчёркивание; пусто = BonnyGermany): ");
        var profileName = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(profileName))
            profileName = DefaultProfileName;
        if (!IsValidProfileName(profileName))
        {
            Console.WriteLine("Имя профиля должно содержать от 1 до 40 символов: A-Z, a-z, 0-9, _ или -.");
            return;
        }

        if (AnyTunnelRunning())
        {
            Console.WriteLine("Сначала отключите активный профиль Bonny WireGuard, затем импортируйте другой.");
            return;
        }

        var configPath = GetConfigPath(profileName);
        if (File.Exists(configPath))
        {
            Console.WriteLine("Профиль с таким именем уже существует. Выберите другое имя; существующий ключ не будет перезаписан.");
            return;
        }

        try
        {
            var config = File.ReadAllText(source);
            ValidateConfig(config);
            Directory.CreateDirectory(ConfigDirectory);
            File.WriteAllText(configPath, config, new UTF8Encoding(false));
            if (!RestrictProfilePermissions(configPath))
            {
                File.Delete(configPath);
                Console.WriteLine("Не удалось ограничить доступ к профилю. Файл не сохранён.");
                return;
            }

            File.WriteAllText(ActiveProfilePath, profileName, new UTF8Encoding(false));
            Console.WriteLine("Профиль " + profileName + " импортирован и выбран.");
            Console.WriteLine("Приватный ключ не выводился на экран и не добавляется в проект.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            Console.WriteLine("Не удалось импортировать профиль: " + ex.GetBaseException().Message);
        }
    }

    private static void SelectProfile()
    {
        var profiles = GetProfileNames();
        if (profiles.Count == 0)
        {
            Console.WriteLine("Сначала импортируйте профиль WireGuard.");
            return;
        }
        if (AnyTunnelRunning())
        {
            Console.WriteLine("Сначала отключите активный профиль, затем выбирайте другой.");
            return;
        }

        Console.WriteLine("Доступные профили:");
        for (var index = 0; index < profiles.Count; index++)
            Console.WriteLine("  " + (index + 1) + ". " + profiles[index]);
        Console.Write("Номер профиля: ");
        if (!int.TryParse(Console.ReadLine()?.Trim(), out var selection) || selection < 1 || selection > profiles.Count)
        {
            Console.WriteLine("Номер не распознан.");
            return;
        }

        try
        {
            Directory.CreateDirectory(ConfigDirectory);
            File.WriteAllText(ActiveProfilePath, profiles[selection - 1], new UTF8Encoding(false));
            Console.WriteLine("Выбран профиль " + profiles[selection - 1] + ".");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.WriteLine("Не удалось сохранить выбранный профиль: " + ex.GetBaseException().Message);
        }
    }

    private static IReadOnlyList<string> GetProfileNames()
    {
        if (!Directory.Exists(ConfigDirectory))
            return [];

        return Directory.GetFiles(ConfigDirectory, "*.conf", SearchOption.TopDirectoryOnly)
            .Select(Path.GetFileNameWithoutExtension)
            .Where(name => name is not null && IsValidProfileName(name))
            .Select(name => name!)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string? GetActiveProfileName()
    {
        try
        {
            if (File.Exists(ActiveProfilePath))
            {
                var selected = File.ReadAllText(ActiveProfilePath).Trim();
                if (IsValidProfileName(selected) && File.Exists(GetConfigPath(selected)))
                    return selected;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        var profiles = GetProfileNames();
        if (profiles.Contains(DefaultProfileName, StringComparer.OrdinalIgnoreCase))
            return DefaultProfileName;
        return profiles.FirstOrDefault();
    }

    private static bool AnyTunnelRunning() =>
        GetProfileNames().Any(profileName => QueryServiceState(profileName) == ServiceState.Running);

    private static bool AnyOtherTunnelRunning(string exceptProfile) =>
        GetProfileNames().Any(profileName =>
            !string.Equals(profileName, exceptProfile, StringComparison.OrdinalIgnoreCase) &&
            QueryServiceState(profileName) == ServiceState.Running);

    private static string GetConfigPath(string profileName) =>
        Path.Combine(ConfigDirectory, profileName + ".conf");

    private static string ServiceNameFor(string profileName) =>
        "WireGuardTunnel$" + profileName;

    private static bool IsValidProfileName(string profileName) =>
        Regex.IsMatch(profileName, @"^[A-Za-z0-9_-]{1,40}$", RegexOptions.CultureInvariant);

    private static void ValidateConfig(string config)
    {
        var currentSection = string.Empty;
        var hasInterface = false;
        var hasPeer = false;
        var hasPrivateKey = false;
        var hasPublicKey = false;
        var hasEndpoint = false;
        var hasFullRouteV4 = false;
        var hasFullRouteV6 = false;

        foreach (var rawLine in config.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
                continue;
            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                currentSection = line[1..^1].Trim();
                hasInterface |= currentSection.Equals("Interface", StringComparison.OrdinalIgnoreCase);
                hasPeer |= currentSection.Equals("Peer", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            var separator = line.IndexOf('=');
            if (separator < 1)
                continue;

            var key = line[..separator].Trim();
            var value = line[(separator + 1)..].Trim();
            if (currentSection.Equals("Interface", StringComparison.OrdinalIgnoreCase) &&
                key.Equals("PrivateKey", StringComparison.OrdinalIgnoreCase) && value.Length > 0)
                hasPrivateKey = true;
            if (currentSection.Equals("Peer", StringComparison.OrdinalIgnoreCase))
            {
                if (key.Equals("PublicKey", StringComparison.OrdinalIgnoreCase) && value.Length > 0)
                    hasPublicKey = true;
                else if (key.Equals("Endpoint", StringComparison.OrdinalIgnoreCase) && value.Contains(':'))
                    hasEndpoint = true;
                else if (key.Equals("AllowedIPs", StringComparison.OrdinalIgnoreCase))
                {
                    var routes = value.Split(',').Select(route => route.Trim());
                    hasFullRouteV4 |= routes.Contains("0.0.0.0/0", StringComparer.Ordinal);
                    hasFullRouteV6 |= routes.Contains("::/0", StringComparer.Ordinal);
                }
            }
        }

        if (!hasInterface || !hasPeer || !hasPrivateKey || !hasPublicKey || !hasEndpoint)
            throw new InvalidDataException("В файле не хватает обязательных полей WireGuard.");
        if (!hasFullRouteV4 || !hasFullRouteV6)
            throw new InvalidDataException("В AllowedIPs должны быть 0.0.0.0/0 и ::/0, иначе IPv6 может пойти в обход туннеля.");
    }

    private static bool RestrictProfilePermissions(string path)
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid))
            return false;

        var result = RunProcess(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "icacls.exe"),
        [
            path,
            "/inheritance:r",
            "/grant:r",
            "*" + sid + ":(F)",
            "*S-1-5-18:(R)",
            "*S-1-5-32-544:(F)"
        ]);
        return result.ExitCode == 0;
    }

    private static string? FindWireGuard()
    {
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var candidates = new[]
        {
            Path.Combine(programFiles, "WireGuard", "wireguard.exe"),
            Path.Combine(programFilesX86, "WireGuard", "wireguard.exe")
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static int RunElevated(string command)
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            Console.Error.WriteLine("Не удалось определить путь к Bonny для запроса прав администратора.");
            return 1;
        }

        try
        {
            var startInfo = new ProcessStartInfo(executable, command)
            {
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = AppContext.BaseDirectory
            };
            using var process = Process.Start(startInfo);
            process?.WaitForExit();
            return process?.ExitCode ?? 1;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            Console.WriteLine("Запрос прав администратора отменён.");
            return 1223;
        }
    }

    private static ServiceState QueryServiceState(string profileName)
    {
        var query = RunSc("query", ServiceNameFor(profileName));
        if (query.ExitCode == 1060)
            return ServiceState.NotInstalled;
        if (query.ExitCode != 0)
            return ServiceState.Unknown;

        var match = Regex.Match(query.Output, @"^\s*[^:\r\n]+\s*:\s*([1-4])\s+\S+.*$", RegexOptions.Multiline);
        if (!match.Success || !int.TryParse(match.Groups[1].Value, out var state))
            return ServiceState.Unknown;

        return state switch
        {
            1 => ServiceState.Stopped,
            2 or 3 => ServiceState.Pending,
            4 => ServiceState.Running,
            _ => ServiceState.Unknown
        };
    }

    private static bool WaitForState(string profileName, ServiceState expected, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (QueryServiceState(profileName) == expected)
                return true;
            Thread.Sleep(400);
        }
        return QueryServiceState(profileName) == expected;
    }

    private static (int ExitCode, string Output) RunSc(params string[] arguments) =>
        RunProcess(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"), arguments);

    private static (int ExitCode, string Output) RunProcess(string executable, IEnumerable<string> arguments)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo);
        if (process is null)
            return (1, "Could not start " + executable);

        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, standardOutput.GetAwaiter().GetResult() + standardError.GetAwaiter().GetResult());
    }

    private static void WriteProcessOutput(string output)
    {
        if (!string.IsNullOrWhiteSpace(output))
            Console.Error.WriteLine(output.Trim());
    }

    private enum ServiceState
    {
        Unknown,
        NotInstalled,
        Stopped,
        Pending,
        Running
    }
}
