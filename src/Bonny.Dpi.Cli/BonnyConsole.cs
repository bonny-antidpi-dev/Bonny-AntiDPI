internal static class BonnyConsole
{
    private static readonly object OutputLock = new();

    public static void WriteRunningPanel()
    {
        lock (OutputLock)
        {
            Console.Title = "Bonny AntiDPI | работает";
            WriteColored("╔══════════════════════════════════════════════════════╗", ConsoleColor.Cyan);
            WriteColored("║  BONNY // ANTIDPI                         [ RUNNING ] ║", ConsoleColor.Cyan);
            WriteColored("╠══════════════════════════════════════════════════════╣", ConsoleColor.DarkCyan);
            WriteColored("║  MODE    : TCP/443 + TLS ClientHello / SNI           ║", ConsoleColor.Gray);
            WriteColored("║  POLICY  : domains.txt                               ║", ConsoleColor.Gray);
            WriteColored("║  CONTROL : Ctrl+C или значок Bonny в системном трее  ║", ConsoleColor.Gray);
            WriteColored("╚══════════════════════════════════════════════════════╝", ConsoleColor.Cyan);
        }
    }

    public static void WriteEngineLog(string message)
    {
        var color = message.Contains("Ошибка", StringComparison.OrdinalIgnoreCase) ||
                    message.Contains("остановлено:", StringComparison.OrdinalIgnoreCase) ||
                    message.Contains("Не удалось", StringComparison.OrdinalIgnoreCase)
            ? ConsoleColor.Red
            : message.Contains("разделён", StringComparison.OrdinalIgnoreCase)
                ? ConsoleColor.Cyan
                : message.Contains("запущен", StringComparison.OrdinalIgnoreCase)
                    ? ConsoleColor.Green
                    : message.Contains("остановлен", StringComparison.OrdinalIgnoreCase)
                        ? ConsoleColor.Yellow
                        : ConsoleColor.Gray;

        lock (OutputLock)
            WriteColored(message, color);
    }

    private static void WriteColored(string message, ConsoleColor color)
    {
        if (Console.IsOutputRedirected)
        {
            Console.WriteLine(message);
            return;
        }

        var previousColor = Console.ForegroundColor;
        try
        {
            Console.ForegroundColor = color;
            Console.WriteLine(message);
        }
        finally
        {
            Console.ForegroundColor = previousColor;
        }
    }
}
