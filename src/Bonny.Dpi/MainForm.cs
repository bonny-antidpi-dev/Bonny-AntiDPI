using System.Diagnostics;
using System.Drawing;

namespace Bonny.Dpi;

internal sealed class MainForm : Form
{
    private readonly Label _status = new();
    private readonly Button _startButton = new();
    private readonly Button _stopButton = new();
    private readonly Button _networkButton = new();
    private readonly ListBox _log = new();
    private readonly string _domainsPath = DomainPolicy.FindListPath(AppContext.BaseDirectory);
    private WinDivertDpiEngine? _engine;

    public MainForm()
    {
        Text = "Bonny AntiDPI";
        MinimumSize = new Size(860, 520);
        Size = new Size(1000, 620);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(18, 22, 31);
        ForeColor = Color.FromArgb(232, 237, 244);
        Font = new Font("Segoe UI", 10F);

        var title = new Label
        {
            Text = "Bonny AntiDPI",
            Font = new Font("Segoe UI Semibold", 22F, FontStyle.Bold),
            ForeColor = Color.FromArgb(108, 185, 255),
            AutoSize = true,
            Location = new Point(24, 20)
        };
        var subtitle = new Label
        {
            Text = "Обработка TCP/TLS и отдельный WireGuard-туннель",
            AutoSize = true,
            ForeColor = Color.FromArgb(177, 188, 203),
            Location = new Point(28, 62)
        };
        _status.Text = "Отключено";
        _status.AutoSize = true;
        _status.Font = new Font("Segoe UI Semibold", 12F, FontStyle.Bold);
        _status.ForeColor = Color.FromArgb(238, 190, 93);
        _status.Location = new Point(28, 105);

        _startButton.Text = "Запустить обход";
        _startButton.Location = new Point(24, 145);
        _startButton.Size = new Size(170, 42);
        _startButton.FlatStyle = FlatStyle.Flat;
        _startButton.BackColor = Color.FromArgb(42, 111, 176);
        _startButton.FlatAppearance.BorderSize = 0;
        _startButton.ForeColor = Color.White;
        _startButton.Click += async (_, _) => await StartEngineAsync();

        _stopButton.Text = "Остановить";
        _stopButton.Location = new Point(204, 145);
        _stopButton.Size = new Size(140, 42);
        _stopButton.FlatStyle = FlatStyle.Flat;
        _stopButton.BackColor = Color.FromArgb(54, 62, 76);
        _stopButton.FlatAppearance.BorderSize = 0;
        _stopButton.ForeColor = Color.White;
        _stopButton.Enabled = false;
        _stopButton.Click += async (_, _) => await StopEngineAsync();

        var domainsButton = new Button
        {
            Text = "Список доменов",
            Location = new Point(354, 145),
            Size = new Size(155, 42),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(39, 47, 60),
            ForeColor = Color.White
        };
        domainsButton.FlatAppearance.BorderSize = 0;
        domainsButton.Click += (_, _) => OpenDomains();

        _networkButton.Text = "Проверить сеть";
        _networkButton.Location = new Point(519, 145);
        _networkButton.Size = new Size(165, 42);
        _networkButton.FlatStyle = FlatStyle.Flat;
        _networkButton.BackColor = Color.FromArgb(39, 47, 60);
        _networkButton.ForeColor = Color.White;
        _networkButton.FlatAppearance.BorderSize = 0;
        _networkButton.Click += async (_, _) => await RunDiagnosticsAsync();

        var wireGuardButton = new Button
        {
            Text = "WireGuard (CMD)",
            Location = new Point(694, 145),
            Size = new Size(185, 42),
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.FromArgb(39, 47, 60),
            ForeColor = Color.White
        };
        wireGuardButton.FlatAppearance.BorderSize = 0;
        wireGuardButton.Click += (_, _) => OpenWireGuardMenu();

        var limits = new Label
        {
            Text = "Bonny DPI обрабатывает TCP/443. QUIC, голос Discord и игровые UDP-пакеты идут через WireGuard, когда полный туннель подключён.\n" +
                   "«Проверить сеть» делает DNS/TCP/TLS-проверку семи сервисов; она не подтверждает обход DPI.",
            AutoSize = true,
            ForeColor = Color.FromArgb(177, 188, 203),
            Location = new Point(28, 205)
        };

        _log.Location = new Point(24, 273);
        _log.Size = new Size(940, 295);
        _log.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        _log.BackColor = Color.FromArgb(11, 14, 21);
        _log.ForeColor = Color.FromArgb(222, 229, 238);
        _log.BorderStyle = BorderStyle.FixedSingle;
        _log.HorizontalScrollbar = true;

        Controls.AddRange([title, subtitle, _status, _startButton, _stopButton, domainsButton, _networkButton, wireGuardButton, limits, _log]);
        FormClosing += OnFormClosing;
        AddLog("Прототип готов. Перед запуском Bonny проверит WinDivert; нужны права администратора.");
    }

    private async Task StartEngineAsync()
    {
        if (_engine is not null)
            return;

        _startButton.Enabled = false;
        _status.Text = "Запуск…";
        _status.ForeColor = Color.FromArgb(238, 190, 93);
        try
        {
            await EnsureWinDivertAsync();
            var policy = DomainPolicy.Load(_domainsPath);
            var engine = new WinDivertDpiEngine(policy);
            engine.Log += AddLog;
            engine.Stopped += OnEngineStopped;
            _engine = engine;
            await Task.Run(engine.Start);
            if (!ReferenceEquals(_engine, engine) || !engine.IsRunning)
                return;

            _status.Text = "Обход включён";
            _status.ForeColor = Color.FromArgb(111, 216, 156);
            _stopButton.Enabled = true;
        }
        catch (Exception ex)
        {
            if (_engine is not null)
            {
                _engine.Log -= AddLog;
                _engine.Stopped -= OnEngineStopped;
                _engine.Dispose();
                _engine = null;
            }
            _status.Text = "Отключено";
            _status.ForeColor = Color.FromArgb(238, 190, 93);
            AddLog("Ошибка запуска: " + ex.GetBaseException().Message);
            _startButton.Enabled = true;
        }
    }

    private async Task EnsureWinDivertAsync()
    {
        var executable = FindCliExecutable();
        if (executable is null)
            throw new FileNotFoundException("Не найдена CMD-версия Bonny. Сначала запустите Build-Bonny.cmd.");

        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(executable)!
        };
        startInfo.ArgumentList.Add("setup");

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Не удалось запустить проверку компонентов WinDivert.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        LogProcessOutput(await outputTask);
        LogProcessOutput(await errorTask);
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Проверка или установка WinDivert завершилась с кодом {process.ExitCode}.");
    }

    private void LogProcessOutput(string output)
    {
        foreach (var line in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
            AddLog(line);
    }

    private async Task StopEngineAsync()
    {
        var engine = _engine;
        if (engine is null)
            return;

        _engine = null;
        _stopButton.Enabled = false;
        _startButton.Enabled = false;
        await Task.Run(engine.Dispose);
        engine.Log -= AddLog;
        engine.Stopped -= OnEngineStopped;
        _status.Text = "Отключено";
        _status.ForeColor = Color.FromArgb(238, 190, 93);
        _startButton.Enabled = true;
    }

    private void OnEngineStopped(WinDivertDpiEngine engine)
    {
        if (IsDisposed || !IsHandleCreated)
            return;

        try { BeginInvoke(new Action(() => _ = HandleEngineStoppedAsync(engine))); }
        catch (InvalidOperationException) { }
    }

    private async Task HandleEngineStoppedAsync(WinDivertDpiEngine engine)
    {
        if (!ReferenceEquals(_engine, engine))
            return;

        _engine = null;
        _startButton.Enabled = false;
        _stopButton.Enabled = false;
        engine.Log -= AddLog;
        engine.Stopped -= OnEngineStopped;
        await Task.Run(engine.Dispose);

        if (IsDisposed)
            return;

        _status.Text = "Обход остановлен";
        _status.ForeColor = Color.FromArgb(238, 190, 93);
        _startButton.Enabled = true;
        AddLog("Движок остановился. При необходимости запустите его снова.");
    }

    private void OpenDomains()
    {
        try
        {
            Process.Start(new ProcessStartInfo("notepad.exe", $"\"{_domainsPath}\"") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            AddLog("Не удалось открыть список доменов: " + ex.Message);
        }
    }

    private async Task RunDiagnosticsAsync()
    {
        _networkButton.Enabled = false;
        AddLog("Сетевая диагностика: проверяю DNS, TCP/443 и TLS для семи сервисов.");
        try
        {
            var results = await NetworkDiagnostics.RunAsync();
            foreach (var result in results)
            {
                var line = string.Format(
                    "{0}: DNS {1}, TCP/443 {2}, TLS {3}, {4} ({5})",
                    result.Service,
                    result.DnsOk ? "OK" : "FAIL",
                    result.Tcp443Ok ? "OK" : "FAIL",
                    result.TlsOk ? "OK" : "FAIL",
                    result.AddressFamily,
                    result.Host);
                AddLog(line);
                if (!string.IsNullOrWhiteSpace(result.Detail))
                    AddLog("  " + result.Detail);
            }
        }
        catch (Exception ex)
        {
            AddLog("Диагностика прервана: " + ex.GetBaseException().Message);
        }
        finally
        {
            if (!IsDisposed)
                _networkButton.Enabled = true;
        }
    }

    private void OpenWireGuardMenu()
    {
        try
        {
            var executable = FindCliExecutable();
            if (executable is null)
            {
                AddLog("Не найдена CMD-версия Bonny. Сначала запустите Build-Bonny.cmd.");
                return;
            }

            var startInfo = new ProcessStartInfo(executable)
            {
                UseShellExecute = true,
                WorkingDirectory = Path.GetDirectoryName(executable)!
            };
            startInfo.ArgumentList.Add("germany");
            _ = Process.Start(startInfo);
            AddLog("Открыто CMD-меню WireGuard: импорт, выбор профиля и переподключение.");
        }
        catch (Exception ex)
        {
            AddLog("Не удалось открыть меню WireGuard: " + ex.GetBaseException().Message);
        }
    }

    private static string? FindCliExecutable()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(
                directory.FullName,
                "src",
                "Bonny.Dpi.Cli",
                "bin",
                "Release",
                "net10.0-windows",
                "win-x64",
                "publish",
                "Bonny.Dpi.Cli.exe");
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }

    private void AddLog(string message)
    {
        if (IsDisposed)
            return;
        if (InvokeRequired)
        {
            try { BeginInvoke(new Action(() => AddLog(message))); }
            catch (InvalidOperationException) { }
            return;
        }

        _log.Items.Add(message);
        while (_log.Items.Count > 500)
            _log.Items.RemoveAt(0);
        if (_log.Items.Count > 0)
            _log.TopIndex = _log.Items.Count - 1;
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_engine is null)
            return;
        var engine = _engine;
        _engine = null;
        engine.Log -= AddLog;
        engine.Stopped -= OnEngineStopped;
        engine.Dispose();
    }
}
