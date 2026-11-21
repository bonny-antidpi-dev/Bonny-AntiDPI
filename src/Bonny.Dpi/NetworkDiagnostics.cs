using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

namespace Bonny.Dpi;

public sealed record NetworkDiagnosticResult(
    string Service,
    string Host,
    bool DnsOk,
    bool Tcp443Ok,
    bool TlsOk,
    string AddressFamily,
    string Detail);

public static class NetworkDiagnostics
{
    private static readonly (string Service, string Host)[] Targets =
    [
        ("Discord", "discord.com"),
        ("Telegram", "telegram.org"),
        ("YouTube", "youtube.com"),
        ("Roblox", "roblox.com"),
        ("TikTok", "tiktok.com"),
        ("SoundCloud", "soundcloud.com")
    ];

    public static async Task<IReadOnlyList<NetworkDiagnosticResult>> RunAsync(
        CancellationToken cancellationToken = default)
    {
        var results = await Task.WhenAll(Targets.Select(target => ProbeAsync(target.Service, target.Host, cancellationToken)));
        return results;
    }

    private static async Task<NetworkDiagnosticResult> ProbeAsync(
        string service,
        string host,
        CancellationToken cancellationToken)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException or OperationCanceledException)
        {
            return new NetworkDiagnosticResult(service, host, false, false, false, "—", Summarize(ex));
        }

        if (addresses.Length == 0)
            return new NetworkDiagnosticResult(service, host, false, false, false, "—", "DNS не вернул адреса.");

        var candidates = addresses
            .Where(address => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .GroupBy(address => address.AddressFamily)
            .Select(group => group.First())
            .OrderBy(address => address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();

        var tcpOk = false;
        var tlsOk = false;
        var family = "—";
        var details = new List<string>();

        foreach (var address in candidates)
        {
            using var client = new TcpClient(address.AddressFamily);
            using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectTimeout.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                await client.ConnectAsync(address, 443, connectTimeout.Token);
                tcpOk = true;
                family = address.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6";

                using var stream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
                using var tlsTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                tlsTimeout.CancelAfter(TimeSpan.FromSeconds(4));
                await stream.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions { TargetHost = host },
                    tlsTimeout.Token);
                tlsOk = true;
                details.Add("TLS handshake успешен");
                break;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException or OperationCanceledException)
            {
                details.Add(string.Concat(address.AddressFamily == AddressFamily.InterNetwork ? "IPv4" : "IPv6", ": ", Summarize(ex)));
            }
        }

        if (!tcpOk && details.Count == 0)
            details.Add("Нет доступных IPv4/IPv6-адресов для проверки.");
        else if (tcpOk && !tlsOk && details.Count == 0)
            details.Add("TCP подключился, TLS handshake не завершился.");

        return new NetworkDiagnosticResult(service, host, true, tcpOk, tlsOk, family, string.Join("; ", details));
    }

    private static string Summarize(Exception exception) => exception switch
    {
        OperationCanceledException => "тайм-аут",
        AuthenticationException => "ошибка TLS/сертификата",
        SocketException socketException => socketException.SocketErrorCode switch
        {
            SocketError.HostNotFound or SocketError.NoData => "имя не найдено",
            SocketError.ConnectionRefused => "соединение отклонено",
            SocketError.TimedOut => "тайм-аут подключения",
            _ => socketException.SocketErrorCode.ToString()
        },
        _ => exception.GetBaseException().Message
    };
}
