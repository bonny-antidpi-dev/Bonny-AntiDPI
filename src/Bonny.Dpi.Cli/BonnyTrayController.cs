using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

internal sealed class BonnyTrayController : IDisposable
{
    private const int HideCommand = 0;
    private const int ShowCommand = 5;

    private readonly Action _requestStop;
    private readonly ManualResetEventSlim _started = new();
    private readonly Thread _thread;
    private SynchronizationContext? _uiContext;
    private ApplicationContext? _applicationContext;
    private Exception? _startupException;
    private bool _disposed;

    public BonnyTrayController(Action requestStop)
    {
        _requestStop = requestStop;
        _thread = new Thread(Run)
        {
            IsBackground = true,
            Name = "Bonny tray icon"
        };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
        _started.Wait();

        if (_startupException is not null)
        {
            _thread.Join();
            throw new InvalidOperationException("Не удалось открыть значок Bonny в системном трее.", _startupException);
        }
    }

    private void Run()
    {
        try
        {
            using var menu = new ContextMenuStrip();
            using var hideItem = new ToolStripMenuItem("Скрыть окно CMD");
            using var showItem = new ToolStripMenuItem("Показать окно CMD");
            using var stopItem = new ToolStripMenuItem("Остановить Bonny");
            using var notifyIcon = new NotifyIcon
            {
                Icon = SystemIcons.Shield,
                Text = "Bonny AntiDPI работает",
                ContextMenuStrip = menu
            };
            _applicationContext = new ApplicationContext();

            hideItem.Click += (_, _) =>
            {
                SetConsoleVisibility(visible: false);
                notifyIcon.ShowBalloonTip(
                    1500,
                    "Bonny AntiDPI работает",
                    "Окно скрыто. Управление доступно через значок Bonny в системном трее.",
                    ToolTipIcon.Info);
            };
            showItem.Click += (_, _) => SetConsoleVisibility(visible: true);
            stopItem.Click += (_, _) => _requestStop();
            notifyIcon.MouseDoubleClick += (_, _) => SetConsoleVisibility(visible: true);
            menu.Items.AddRange([hideItem, showItem, new ToolStripSeparator(), stopItem]);
            notifyIcon.Visible = true;

            using var readyTimer = new System.Windows.Forms.Timer { Interval = 1 };
            readyTimer.Tick += (_, _) =>
            {
                readyTimer.Stop();
                _uiContext = SynchronizationContext.Current;
                _started.Set();
            };
            readyTimer.Start();
            Application.Run(_applicationContext);
        }
        catch (Exception ex)
        {
            _startupException = ex;
            _started.Set();
        }
        finally
        {
            _applicationContext?.Dispose();
        }
    }

    public void ShowConsole() => SetConsoleVisibility(visible: true);

    private static void SetConsoleVisibility(bool visible)
    {
        var window = GetConsoleWindow();
        if (window != IntPtr.Zero)
            _ = ShowWindow(window, visible ? ShowCommand : HideCommand);
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;

        SetConsoleVisibility(visible: true);
        if (_thread.IsAlive)
        {
            var context = _uiContext;
            var applicationContext = _applicationContext;
            if (context is null || applicationContext is null)
                throw new InvalidOperationException("Поток значка Bonny не инициализировался корректно.");

            context.Post(_ => applicationContext.ExitThread(), null);
            if (!_thread.Join(TimeSpan.FromSeconds(5)))
                throw new TimeoutException("Не удалось закрыть значок Bonny в системном трее.");
        }

        _started.Dispose();
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ShowWindow(IntPtr window, int command);
}
