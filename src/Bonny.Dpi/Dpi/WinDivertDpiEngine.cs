using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Bonny.Dpi;

internal sealed class WinDivertDpiEngine : IDisposable
{
    private const string CaptureFilter = "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0 and !loopback and !impostor";
    private static readonly TimeSpan PendingTimeout = TimeSpan.FromMilliseconds(180);
    private static readonly TimeSpan FlowLifetime = TimeSpan.FromSeconds(30);
    private const int MaximumTrackedFlows = 1024;
    private const int MaximumPendingPackets = 16;
    private const int MaximumPendingBytes = 32 * 1024;

    private readonly object _gate = new();
    private readonly DomainPolicy _policy;
    private readonly Dictionary<string, PendingFlow> _flows = new(StringComparer.Ordinal);
    private IntPtr _handle;
    private Task? _reader;
    private System.Threading.Timer? _expiryTimer;
    private volatile bool _running;
    private bool _flowCapacityWarningLogged;

    public event Action<string>? Log;
    public event Action<WinDivertDpiEngine>? Stopped;
    public bool IsRunning => _running;

    internal static bool CanTrackFlow(int currentFlowCount) => currentFlowCount < MaximumTrackedFlows;

    public WinDivertDpiEngine(DomainPolicy policy) => _policy = policy;

    public void Start()
    {
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess)
            throw new PlatformNotSupportedException("Bonny DPI сейчас рассчитан на Windows x64.");
        if (!IsAdministrator())
            throw new UnauthorizedAccessException("Для запуска Bonny нужны права администратора.");

        var nativeDirectory = FindNativeDirectory(AppContext.BaseDirectory);
        var dllPath = Path.Combine(nativeDirectory, "WinDivert.dll");
        var driverPath = Path.Combine(nativeDirectory, "WinDivert64.sys");
        if (!File.Exists(dllPath) || !File.Exists(driverPath))
            throw new FileNotFoundException("Не найдены native\\WinDivert.dll и native\\WinDivert64.sys. Смотрите native\\README.md.");
        if (!WinDivertNative.SetDllDirectory(nativeDirectory))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось добавить папку WinDivert в поиск DLL.");

        _handle = WinDivertNative.WinDivertOpen(CaptureFilter, WinDivertNative.LayerNetwork, 0, 0);
        if (_handle == IntPtr.Zero || _handle == WinDivertNative.InvalidHandle)
        {
            var error = Marshal.GetLastWin32Error();
            _handle = IntPtr.Zero;
            throw new Win32Exception(error, "WinDivert не запустился. Проверьте права администратора и состояние драйвера.");
        }

        _running = true;
        _expiryTimer = new System.Threading.Timer(_ => ExpireFlows(), null, 50, 50);
        _reader = Task.Run(CaptureLoop);
        WriteLog("Bonny запущен: исходящий TCP/443, только домены из domains.txt.");
        WriteLog("Метод: разделение ClientHello перед SNI. QUIC/UDP пока не обрабатывается.");
    }

    internal static string FindNativeDirectory(string baseDirectory)
    {
        var localDirectory = Path.Combine(baseDirectory, "native");
        if (HasNativeFiles(localDirectory))
            return localDirectory;

        for (var directory = new DirectoryInfo(baseDirectory); directory is not null; directory = directory.Parent)
        {
            var cliNativeDirectory = Path.Combine(
                directory.FullName,
                "src",
                "Bonny.Dpi.Cli",
                "bin",
                "Release",
                "net10.0-windows",
                "win-x64",
                "publish",
                "native");
            if (HasNativeFiles(cliNativeDirectory))
                return cliNativeDirectory;
        }

        return localDirectory;
    }

    private static bool HasNativeFiles(string directory) =>
        File.Exists(Path.Combine(directory, "WinDivert.dll")) &&
        File.Exists(Path.Combine(directory, "WinDivert64.sys"));

    private void CaptureLoop()
    {
        var packetBuffer = new byte[65_535];
        var addressBuffer = new byte[WinDivertNative.AddressSize];
        try
        {
            while (_running)
            {
                if (!WinDivertNative.WinDivertRecv(_handle, packetBuffer, (uint)packetBuffer.Length, out var received, addressBuffer))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (!_running)
                        break;
                    throw new Win32Exception(error, "WinDivert не смог получить пакет.");
                }

                if (received == 0 || received > packetBuffer.Length)
                    continue;

                var packetLength = (int)received;
                var packet = packetBuffer.AsSpan(0, packetLength);
                if (!TcpPacketInfo.TryParse(packet, out var view))
                {
                    Send(packetBuffer, packetLength, addressBuffer);
                    continue;
                }

                HandlePacket(packetBuffer, packetLength, addressBuffer, view);
            }
        }
        catch (Exception ex)
        {
            WriteLog("Остановлено: " + ex.GetBaseException().Message);
            _running = false;
        }
        finally
        {
            FlushAllPending();
            try { Stopped?.Invoke(this); }
            catch { /* UI notifications must not interrupt packet cleanup. */ }
        }
    }

    private void HandlePacket(byte[] packet, int packetLength, byte[] address, TcpPacketInfo view)
    {
        lock (_gate)
        {
            if (!_flows.TryGetValue(view.FlowKey, out var flow))
            {
                if (!CanTrackFlow(_flows.Count))
                {
                    if (!_flowCapacityWarningLogged)
                    {
                        _flowCapacityWarningLogged = true;
                        WriteLog($"Достигнут лимит {_flows.Count} отслеживаемых потоков; новые соединения передаются без изменений.");
                    }
                    Send(packet, packetLength, address);
                    return;
                }

                flow = new PendingFlow();
                _flows.Add(view.FlowKey, flow);
            }

            flow.LastSeenUtc = DateTime.UtcNow;
            if (flow.Finalized)
            {
                Send(packet, packetLength, address);
                return;
            }

            // SYN-data and unusual TCP extensions are passed through untouched.
            if ((view.TcpFlags & 0x02) != 0)
            {
                flow.Finalized = true;
                Send(packet, packetLength, address);
                return;
            }

            if (flow.HasSequence && view.SequenceNumber != flow.NextSequence)
            {
                CompleteUnchanged(flow, "порядок TCP-пакетов изменился");
                Send(packet, packetLength, address);
                return;
            }

            if (!flow.HasSequence)
            {
                flow.HasSequence = true;
                flow.NextSequence = view.SequenceNumber;
            }

            var ownedPacket = packet.AsSpan(0, packetLength).ToArray();
            var ownedAddress = (byte[])address.Clone();
            flow.Packets.Add(new CapturedPacket(ownedPacket, ownedAddress, view));
            var payload = packet.AsSpan(view.PayloadOffset, view.PayloadLength);
            flow.Stream.Write(payload);
            flow.NextSequence = unchecked(view.SequenceNumber + (uint)view.PayloadLength);

            if (flow.Packets.Count > MaximumPendingPackets || flow.Stream.Length > MaximumPendingBytes)
            {
                CompleteUnchanged(flow, "лимит ожидания ClientHello достигнут");
                return;
            }

            var bytes = flow.Stream.GetBuffer().AsSpan(0, checked((int)flow.Stream.Length));
            var status = TlsClientHelloParser.Parse(bytes, out var hello);
            switch (status)
            {
                case ClientHelloParseStatus.NeedMoreData:
                    return;
                case ClientHelloParseStatus.ClientHelloWithSni:
                    if (!_policy.Includes(hello.Host))
                    {
                        CompleteUnchanged(flow, "не целевой домен " + hello.Host);
                        return;
                    }

                    CompleteTarget(flow, hello);
                    return;
                case ClientHelloParseStatus.ClientHelloWithoutSni:
                    CompleteUnchanged(flow, "в ClientHello нет видимого SNI");
                    return;
                default:
                    CompleteUnchanged(flow, "это не поддерживаемый ClientHello");
                    return;
            }
        }
    }

    private void CompleteTarget(PendingFlow flow, ClientHelloInfo hello)
    {
        flow.Finalized = true;
        if (!TrySplitFlow(flow, hello.SniHostOffset, out var output, out var didSplit))
        {
            SendAll(flow.Packets);
            WriteLog($"{hello.Host}: ClientHello сохранён без изменений (граница SNI уже проходит между пакетами).");
            ReleaseBufferedData(flow);
            return;
        }

        foreach (var item in output)
            Send(item);
        WriteLog(didSplit
            ? $"{hello.Host}: ClientHello разделён перед SNI."
            : $"{hello.Host}: пакет уже разделён перед SNI.");
        ReleaseBufferedData(flow);
    }

    internal static bool TrySplitFlow(
        PendingFlow flow,
        int splitOffset,
        out List<CapturedPacket> output,
        out bool didSplit,
        Func<byte[], byte[], bool>? checksumCalculator = null)
    {
        output = new List<CapturedPacket>(flow.Packets.Count + 1);
        didSplit = false;
        var streamOffset = 0;
        checksumCalculator ??= CalculateNativeChecksums;

        foreach (var packet in flow.Packets)
        {
            if (packet.View is not { } view)
                return false;

            var end = streamOffset + view.PayloadLength;
            if (splitOffset > streamOffset && splitOffset < end)
            {
                if (!TcpPacketInfo.TrySplit(packet.Data, splitOffset - streamOffset, out var first, out var second))
                    return false;
                var firstAddress = (byte[])packet.Address.Clone();
                var secondAddress = (byte[])packet.Address.Clone();
                if (!checksumCalculator(first, firstAddress) || !checksumCalculator(second, secondAddress))
                    return false;
                output.Add(new CapturedPacket(first, firstAddress, TcpPacketInfo.TryParse(first, out var firstView) ? firstView : null));
                output.Add(new CapturedPacket(second, secondAddress, TcpPacketInfo.TryParse(second, out var secondView) ? secondView : null));
                didSplit = true;
            }
            else
            {
                output.Add(packet);
            }
            streamOffset = end;
        }

        return splitOffset > 0 && splitOffset < streamOffset;
    }

    private static bool CalculateNativeChecksums(byte[] packet, byte[] address) =>
        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, address, 0);

    private void CompleteUnchanged(PendingFlow flow, string reason)
    {
        flow.Finalized = true;
        SendAll(flow.Packets);
        if (flow.Packets.Count > 1)
            WriteLog("ClientHello пропущен без изменений: " + reason + ".");
        ReleaseBufferedData(flow);
    }

    private void ExpireFlows()
    {
        lock (_gate)
        {
            var now = DateTime.UtcNow;
            foreach (var entry in _flows.ToArray())
            {
                var flow = entry.Value;
                var age = now - flow.LastSeenUtc;
                if (!flow.Finalized && age >= PendingTimeout)
                    CompleteUnchanged(flow, "истекло время ожидания продолжения ClientHello");
                else if (flow.Finalized && age >= FlowLifetime)
                {
                    flow.Stream.Dispose();
                    _flows.Remove(entry.Key);
                }
            }
        }
    }

    private void FlushAllPending()
    {
        lock (_gate)
        {
            foreach (var flow in _flows.Values.Where(x => !x.Finalized))
                CompleteUnchanged(flow, "остановка движка");
        }
    }

    private static void ReleaseBufferedData(PendingFlow flow)
    {
        flow.Packets.Clear();
        flow.Stream.SetLength(0);
        flow.Stream.Capacity = 0;
    }

    private void SendAll(IEnumerable<CapturedPacket> packets)
    {
        foreach (var packet in packets)
            Send(packet);
    }

    private void Send(CapturedPacket packet)
        => Send(packet.Data, packet.Data.Length, packet.Address);

    private void Send(byte[] packet, int packetLength, byte[] address)
    {
        if (_handle == IntPtr.Zero)
            return;
        if (!WinDivertNative.WinDivertSend(_handle, packet, (uint)packetLength, out _, address))
            WriteLog("Не удалось вернуть пакет в сеть: " + new Win32Exception(Marshal.GetLastWin32Error()).Message);
    }

    private void WriteLog(string message)
    {
        try { Log?.Invoke($"[{DateTime.Now:HH:mm:ss}] {message}"); }
        catch { /* Logging must not interrupt packet forwarding. */ }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public void Stop()
    {
        if (_handle == IntPtr.Zero)
            return;

        _running = false;
        _expiryTimer?.Dispose();
        _expiryTimer = null;
        _ = WinDivertNative.WinDivertShutdown(_handle, WinDivertNative.ShutdownReceive);
        try { _reader?.GetAwaiter().GetResult(); }
        catch (AggregateException) { }
        FlushAllPending();
        _ = WinDivertNative.WinDivertClose(_handle);
        _handle = IntPtr.Zero;
        WriteLog("Bonny остановлен.");
    }

    public void Dispose() => Stop();

    internal sealed class PendingFlow
    {
        public readonly List<CapturedPacket> Packets = new();
        public readonly MemoryStream Stream = new();
        public DateTime LastSeenUtc = DateTime.UtcNow;
        public uint NextSequence;
        public bool HasSequence;
        public bool Finalized;
    }

    internal sealed record CapturedPacket(byte[] Data, byte[] Address, TcpPacketInfo? View);
}
