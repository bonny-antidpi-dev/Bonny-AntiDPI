using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Bonny.Dpi;

var tests = new (string Name, Action Run)[]
{
    ("TLS ClientHello reads the SNI and split offset", ParseSni),
    ("TLS parser reads a ClientHello from the Windows TLS stack", ParsePlatformClientHello),
    ("TLS ClientHello waits for a complete record", IncompleteHello),
    ("TLS ClientHello fragmented across records maps the SNI offset", FragmentedHello),
    ("TLS ClientHello without SNI remains untouched", NoSni),
    ("Packet parser reads exact packets from a shared receive buffer", ParseSharedReceiveBuffer),
    ("Domain policy matches roots and subdomains only", DomainPolicyMatches),
    ("Configured policy covers the seven configured services", ConfiguredServiceDomains),
    ("Discord web and CDN hostnames are covered by TCP domain policy", DiscordDomainCoverage),
    ("Spotify web, API, and CDN domains are covered by TCP domain policy", SpotifyDomainCoverage),
    ("IPv4 TCP split preserves stream and checksums", SplitIpv4),
    ("IPv6 TCP split preserves stream and checksum", SplitIpv6),
    ("IPv6 Hop-by-Hop and Destination options preserve split checksums", SplitIpv6WithOptions),
    ("Unsafe IPv6 routing, fragments, and Home Address options pass through", RejectUnsafeIpv6Headers),
    ("Buffered TCP flow splits at the ClientHello SNI offset", SplitBufferedFlow),
    ("Flow table limit passes new flows through at capacity", FlowCapacityLimit),
    ("GUI locates the verified CMD-published WinDivert runtime", NativeRuntimeResolution)
};

var failures = 0;
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine("PASS " + test.Name);
    }
    catch (Exception ex)
    {
        failures++;
        Console.Error.WriteLine("FAIL " + test.Name + ": " + ex.Message);
    }
}

Console.WriteLine($"{tests.Length - failures}/{tests.Length} checks passed.");
return failures == 0 ? 0 : 1;

static void ParseSni()
{
    var hello = MakeClientHello("discord.com");
    var status = TlsClientHelloParser.Parse(hello, out var parsed);
    Equal(ClientHelloParseStatus.ClientHelloWithSni, status);
    Equal("discord.com", parsed.Host);
    Equal(hello.Length, parsed.MessageLength);
    Equal("discord.com", Encoding.ASCII.GetString(hello, parsed.SniHostOffset, parsed.Host.Length));
}

static void ParsePlatformClientHello()
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var endpoint = (IPEndPoint)listener.LocalEndpoint;
    var acceptTask = listener.AcceptTcpClientAsync();
    using var client = new TcpClient();
    client.Connect(endpoint.Address, endpoint.Port);
    using var server = acceptTask.GetAwaiter().GetResult();
    using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);

    var authenticateTask = ssl.AuthenticateAsClientAsync(
        new SslClientAuthenticationOptions { TargetHost = "discord.com" },
        cancellation.Token);
    var serverStream = server.GetStream();
    serverStream.ReadTimeout = 5000;
    var received = new List<byte>();
    var buffer = new byte[4096];
    ClientHelloParseStatus status;
    ClientHelloInfo parsed;

    do
    {
        var count = serverStream.Read(buffer, 0, buffer.Length);
        if (count <= 0)
            throw new InvalidOperationException("The TLS stack closed before sending ClientHello.");
        received.AddRange(buffer.AsSpan(0, count).ToArray());
        status = TlsClientHelloParser.Parse(received.ToArray(), out parsed);
    } while (status == ClientHelloParseStatus.NeedMoreData);

    cancellation.Cancel();
    try { authenticateTask.GetAwaiter().GetResult(); }
    catch (OperationCanceledException) { }
    catch (IOException) { }

    Equal(ClientHelloParseStatus.ClientHelloWithSni, status);
    Equal("discord.com", parsed.Host);
    Equal("discord.com", Encoding.ASCII.GetString(received.ToArray(), parsed.SniHostOffset, parsed.Host.Length));
}

static void IncompleteHello()
{
    var hello = MakeClientHello("youtube.com");
    var status = TlsClientHelloParser.Parse(hello.AsSpan(0, 12), out _);
    Equal(ClientHelloParseStatus.NeedMoreData, status);
}

static void FragmentedHello()
{
    var singleRecord = MakeClientHello("telegram.org");
    Equal(ClientHelloParseStatus.ClientHelloWithSni, TlsClientHelloParser.Parse(singleRecord, out var original));
    var logicalHostOffset = original.SniHostOffset - 5;
    var cuts = new[] { 2, logicalHostOffset - 3, logicalHostOffset + 3 };

    foreach (var cut in cuts)
    {
        var fragmented = MakeFragmentedClientHello(singleRecord, cut);
        if (cut == cuts[0])
        {
            var firstRecordLength = cut + 5;
            Equal(ClientHelloParseStatus.NeedMoreData,
                TlsClientHelloParser.Parse(fragmented.AsSpan(0, firstRecordLength), out _));
        }

        Equal(ClientHelloParseStatus.ClientHelloWithSni, TlsClientHelloParser.Parse(fragmented, out var parsed));
        Equal("telegram.org", parsed.Host);
        var expectedHostOffset = original.SniHostOffset + (cut <= logicalHostOffset ? 5 : 0);
        Equal(expectedHostOffset, parsed.SniHostOffset);
        Equal(fragmented.Length, parsed.MessageLength);
        var contiguousHostBytes = cut <= logicalHostOffset
            ? parsed.Host.Length
            : Math.Min(parsed.Host.Length, cut - logicalHostOffset);
        Equal(parsed.Host[..contiguousHostBytes],
            Encoding.ASCII.GetString(fragmented, parsed.SniHostOffset, contiguousHostBytes));
    }
}

static void NoSni()
{
    var hello = MakeClientHello(null);
    var status = TlsClientHelloParser.Parse(hello, out _);
    Equal(ClientHelloParseStatus.ClientHelloWithoutSni, status);
}

static void ParseSharedReceiveBuffer()
{
    var payload = MakeClientHello("discord.com");
    var packet = MakeIpv4Packet(payload, 0x10203040);
    var receiveBuffer = new byte[65_535];
    packet.CopyTo(receiveBuffer, 0);

    True(TcpPacketInfo.TryParse(receiveBuffer.AsSpan(0, packet.Length), out var parsed));
    Equal(packet.Length, parsed.PacketLength);
    Equal(payload.Length, parsed.PayloadLength);
    Equal("4:0A000002:51515>5DB8D822:443", parsed.FlowKey);
}

static void DomainPolicyMatches()
{
    var file = Path.GetTempFileName();
    try
    {
        File.WriteAllText(file, "discord.com\r\nyoutube.com\r\ngooglevideo.com\r\n");
        var policy = DomainPolicy.Load(file);
        True(policy.Includes("discord.com"), "Discord root domain");
        True(policy.Includes("gateway.discord.com"), "Discord subdomain");
        True(policy.Includes("r1---sn.googlevideo.com"), "Googlevideo subdomain");
        True(!policy.Includes("evil-discord.com"), "lookalike domain");
        True(!policy.Includes("notyoutube.com"), "domain without a label boundary");
    }
    finally
    {
        File.Delete(file);
    }
}

static void ConfiguredServiceDomains()
{
    var policy = DomainPolicy.Load(Path.Combine(AppContext.BaseDirectory, "domains.txt"));
    foreach (var host in new[]
    {
        "discord.com", "gateway.discord.com",
        "telegram.org", "api.telegram.org",
        "youtube.com", "r1---sn.googlevideo.com",
        "roblox.com", "assetdelivery.roblox.com",
        "tiktok.com", "www.tiktok.com",
        "soundcloud.com", "api-v2.soundcloud.com",
        "sndcdn.com", "cf-media.sndcdn.com",
        "spotify.com", "api.spotify.com", "open.spotify.com", "accounts.spotify.com",
        "spotify.net", "spotifycdn.com", "spotifycdn.net", "p.scdn.co",
        "meduza.io", "currenttime.tv", "ovdinfo.org", "bbc.com"
    })
        True(policy.Includes(host), "configured service hostname " + host);

    True(!policy.Includes("example.com"), "unlisted domain remains outside the policy");
    True(!policy.Includes("wikipedia.org"), "source links are not mistaken for blocked media sites");
    True(!policy.Includes("web.archive.org"), "archive links are not mistaken for publication sites");
}

static void DiscordDomainCoverage()
{
    var policy = DomainPolicy.Load(Path.Combine(AppContext.BaseDirectory, "domains.txt"));
    foreach (var host in new[]
    {
        "discord.com",
        "gateway.discord.com",
        "discordapp.com",
        "cdn.discordapp.com",
        "discordapp.net",
        "media.discordapp.net",
        "discord.gg",
        "discord.media"
    })
        True(policy.Includes(host), "Discord TCP/TLS hostname " + host);

    True(!policy.Includes("discord.com.example.org"), "lookalike Discord hostname");
}

static void SpotifyDomainCoverage()
{
    var policy = DomainPolicy.Load(Path.Combine(AppContext.BaseDirectory, "domains.txt"));
    foreach (var host in new[]
    {
        "spotify.com",
        "api.spotify.com",
        "open.spotify.com",
        "accounts.spotify.com",
        "spotify.net",
        "spotifycdn.com",
        "spotifycdn.net",
        "p.scdn.co"
    })
        True(policy.Includes(host), "Spotify TCP/TLS hostname " + host);

    True(!policy.Includes("spotify.com.example.org"), "lookalike Spotify hostname");
}

static void SplitIpv4()
{
    var hello = MakeClientHello("roblox.com");
    TlsClientHelloParser.Parse(hello, out var parsed);
    var original = MakeIpv4Packet(hello, 0x10203040);
    True(TcpPacketInfo.TrySplit(original, parsed.SniHostOffset, out var first, out var second));
    ValidateSplit(original, first, second, hello, parsed.SniHostOffset, 0x10203040, 4);
}

static void SplitIpv6()
{
    var hello = MakeClientHello("tiktok.com");
    TlsClientHelloParser.Parse(hello, out var parsed);
    var original = MakeIpv6Packet(hello, 0x50607080);
    True(TcpPacketInfo.TrySplit(original, parsed.SniHostOffset, out var first, out var second));
    ValidateSplit(original, first, second, hello, parsed.SniHostOffset, 0x50607080, 6);
}

static void SplitIpv6WithOptions()
{
    var hello = MakeClientHello("api.telegram.org");
    Equal(ClientHelloParseStatus.ClientHelloWithSni, TlsClientHelloParser.Parse(hello, out var parsed));
    const uint sequence = 0x708090a0;
    var original = MakeIpv6PacketWithOptions(hello, sequence);
    True(TcpPacketInfo.TryParse(original, out var view));
    Equal(56, view.TcpOffset);
    True(TcpPacketInfo.TrySplit(original, parsed.SniHostOffset, out var first, out var second));
    ValidateSplit(original, first, second, hello, parsed.SniHostOffset, sequence, 6);
}

static void RejectUnsafeIpv6Headers()
{
    var payload = MakeClientHello("discord.com");
    var routing = MakeIpv6Packet(payload, 0x11223344);
    routing[6] = 43;
    routing[40] = 6;
    True(!TcpPacketInfo.TryParse(routing, out _), "routing header changes the checksum pseudo-header");

    var fragment = MakeIpv6Packet(payload, 0x22334455);
    fragment[6] = 44;
    fragment[40] = 6;
    True(!TcpPacketInfo.TryParse(fragment, out _), "fragmented IPv6 packets are left untouched");

    var homeAddress = MakeIpv6PacketWithOptions(payload, 0x33445566, includeHomeAddress: true);
    True(!TcpPacketInfo.TryParse(homeAddress, out _), "Home Address option changes the TCP pseudo-header");

    var malformed = MakeIpv6PacketWithOptions(payload, 0x44556677);
    malformed[41] = byte.MaxValue;
    True(!TcpPacketInfo.TryParse(malformed, out _), "truncated extension headers are rejected");
}

static void SplitBufferedFlow()
{
    var hello = MakeClientHello("discord.com");
    Equal(ClientHelloParseStatus.ClientHelloWithSni, TlsClientHelloParser.Parse(hello, out var parsed));
    var firstEnd = parsed.SniHostOffset - 8;
    var secondEnd = parsed.SniHostOffset + 3;
    var pieces = new[]
    {
        hello.AsSpan(0, firstEnd).ToArray(),
        hello.AsSpan(firstEnd, secondEnd - firstEnd).ToArray(),
        hello.AsSpan(secondEnd).ToArray()
    };
    var flow = new WinDivertDpiEngine.PendingFlow();
    uint sequence = 0x60708090;
    foreach (var piece in pieces)
    {
        var packet = MakeIpv4Packet(piece, sequence);
        True(TcpPacketInfo.TryParse(packet, out var view));
        flow.Packets.Add(new WinDivertDpiEngine.CapturedPacket(packet, new byte[80], view));
        sequence = unchecked(sequence + (uint)piece.Length);
    }

    True(WinDivertDpiEngine.TrySplitFlow(flow, parsed.SniHostOffset, out var output, out var didSplit,
        static (_, _) => true));
    True(didSplit, "the SNI boundary crossed the second buffered packet");
    Equal(4, output.Count);
    var splitHead = output[1].View ?? throw new InvalidOperationException("Missing TCP header on split head.");
    var splitTail = output[2].View ?? throw new InvalidOperationException("Missing TCP header on split tail.");
    Equal(parsed.SniHostOffset - firstEnd, splitHead.PayloadLength);
    Equal(unchecked(0x60708090u + (uint)parsed.SniHostOffset), splitTail.SequenceNumber);
    Equal(0xffff, SumTcpChecksum(output[1].Data, splitHead));
    Equal(0xffff, SumTcpChecksum(output[2].Data, splitTail));

    using var reassembled = new MemoryStream();
    foreach (var packet in output)
    {
        var view = packet.View ?? throw new InvalidOperationException("Missing TCP header in output packet.");
        reassembled.Write(packet.Data.AsSpan(view.PayloadOffset, view.PayloadLength));
    }
    SequenceEqual(hello, reassembled.ToArray());
}

static void FlowCapacityLimit()
{
    True(WinDivertDpiEngine.CanTrackFlow(0), "empty flow table accepts a connection");
    True(WinDivertDpiEngine.CanTrackFlow(1023), "last available slot accepts a connection");
    True(!WinDivertDpiEngine.CanTrackFlow(1024), "full flow table rejects additional state");
    True(!WinDivertDpiEngine.CanTrackFlow(2048), "over-capacity state is never admitted");
}

static void ValidateSplit(byte[] original, byte[] first, byte[] second, byte[] payload, int split, uint sequence, int ipVersion)
{
    True(TcpPacketInfo.TryParse(first, out var firstView));
    True(TcpPacketInfo.TryParse(second, out var secondView));
    Equal(ipVersion, firstView.IpVersion);
    Equal(ipVersion, secondView.IpVersion);
    Equal(split, firstView.PayloadLength);
    Equal(payload.Length - split, secondView.PayloadLength);
    SequenceEqual(payload.AsSpan(0, split), first.AsSpan(firstView.PayloadOffset, firstView.PayloadLength));
    SequenceEqual(payload.AsSpan(split), second.AsSpan(secondView.PayloadOffset, secondView.PayloadLength));
    Equal(unchecked(sequence + (uint)split), secondView.SequenceNumber);
    True((firstView.TcpFlags & 0x09) == 0); // FIN and PSH must stay on the tail segment.
    True((secondView.TcpFlags & 0x08) != 0);

    if (ipVersion == 4)
    {
        Equal(first.Length, BinaryPrimitives.ReadUInt16BigEndian(first.AsSpan(2, 2)));
        Equal(second.Length, BinaryPrimitives.ReadUInt16BigEndian(second.AsSpan(2, 2)));
        Equal(unchecked((ushort)(BinaryPrimitives.ReadUInt16BigEndian(original.AsSpan(4, 2)) + 1)),
            BinaryPrimitives.ReadUInt16BigEndian(second.AsSpan(4, 2)));
        Equal(0xffff, SumWords(first.AsSpan(0, firstView.IpHeaderLength)));
        Equal(0xffff, SumTcpChecksum(first, firstView));
        Equal(0xffff, SumTcpChecksum(second, secondView));
    }
    else
    {
        Equal(first.Length - 40, BinaryPrimitives.ReadUInt16BigEndian(first.AsSpan(4, 2)));
        Equal(second.Length - 40, BinaryPrimitives.ReadUInt16BigEndian(second.AsSpan(4, 2)));
        Equal(0xffff, SumTcpChecksum(first, firstView));
        Equal(0xffff, SumTcpChecksum(second, secondView));
    }

    True(original.Length > first.Length);
}

static int SumTcpChecksum(byte[] packet, TcpPacketInfo view)
{
    ulong sum = 0;
    var tcpLength = packet.Length - view.TcpOffset;
    if (view.IpVersion == 4)
    {
        sum = AddWords(packet.AsSpan(12, 8), sum);
        sum += 6;
        sum += (uint)tcpLength;
    }
    else
    {
        sum = AddWords(packet.AsSpan(8, 32), sum);
        sum += (uint)(tcpLength >> 16);
        sum += (uint)(tcpLength & 0xffff);
        sum += 6;
    }
    sum = AddWords(packet.AsSpan(view.TcpOffset, tcpLength), sum);
    while ((sum >> 16) != 0)
        sum = (sum & 0xffff) + (sum >> 16);
    return (int)sum;
}

static int SumWords(ReadOnlySpan<byte> bytes)
{
    ulong sum = AddWords(bytes, 0);
    while ((sum >> 16) != 0)
        sum = (sum & 0xffff) + (sum >> 16);
    return (int)sum;
}

static ulong AddWords(ReadOnlySpan<byte> bytes, ulong sum)
{
    var index = 0;
    for (; index + 1 < bytes.Length; index += 2)
        sum += (uint)((bytes[index] << 8) | bytes[index + 1]);
    if (index < bytes.Length)
        sum += (uint)(bytes[index] << 8);
    return sum;
}

static void NativeRuntimeResolution()
{
    var root = Path.Combine(Path.GetTempPath(), "Bonny-Native-" + Guid.NewGuid().ToString("N"));
    var guiBase = Path.Combine(root, "src", "Bonny.Dpi", "bin", "Release", "net10.0-windows", "win-x64", "publish");
    var cliNative = Path.Combine(root, "src", "Bonny.Dpi.Cli", "bin", "Release", "net10.0-windows", "win-x64", "publish", "native");
    var localNative = Path.Combine(guiBase, "native");
    try
    {
        Directory.CreateDirectory(cliNative);
        File.WriteAllBytes(Path.Combine(cliNative, "WinDivert.dll"), []);
        File.WriteAllBytes(Path.Combine(cliNative, "WinDivert64.sys"), []);
        Equal(cliNative, WinDivertDpiEngine.FindNativeDirectory(guiBase));

        Directory.CreateDirectory(localNative);
        File.WriteAllBytes(Path.Combine(localNative, "WinDivert.dll"), []);
        File.WriteAllBytes(Path.Combine(localNative, "WinDivert64.sys"), []);
        Equal(localNative, WinDivertDpiEngine.FindNativeDirectory(guiBase));

        File.Delete(Path.Combine(localNative, "WinDivert64.sys"));
        Equal(cliNative, WinDivertDpiEngine.FindNativeDirectory(guiBase));
    }
    finally
    {
        if (Directory.Exists(root))
            Directory.Delete(root, recursive: true);
    }
}

static byte[] MakeClientHello(string? host)
{
    using var body = new MemoryStream();
    body.Write([0x03, 0x03]);
    body.Write(new byte[32]);
    body.WriteByte(0); // empty session ID
    body.Write([0x00, 0x02, 0x13, 0x01]); // one cipher suite
    body.Write([0x01, 0x00]); // one null compression method

    var extensions = new List<byte>();
    if (host is not null)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var sniData = new List<byte> { (byte)((name.Length + 3) >> 8), (byte)(name.Length + 3), 0,
            (byte)(name.Length >> 8), (byte)name.Length };
        sniData.AddRange(name);
        extensions.AddRange([0x00, 0x00, (byte)(sniData.Count >> 8), (byte)sniData.Count]);
        extensions.AddRange(sniData);
    }

    body.WriteByte((byte)(extensions.Count >> 8));
    body.WriteByte((byte)extensions.Count);
    body.Write(extensions.ToArray());

    var bodyBytes = body.ToArray();
    var handshake = new byte[4 + bodyBytes.Length];
    handshake[0] = 0x01;
    handshake[1] = (byte)(bodyBytes.Length >> 16);
    handshake[2] = (byte)(bodyBytes.Length >> 8);
    handshake[3] = (byte)bodyBytes.Length;
    bodyBytes.CopyTo(handshake, 4);

    var record = new byte[5 + handshake.Length];
    record[0] = 0x16;
    record[1] = 0x03;
    record[2] = 0x01;
    BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), (ushort)handshake.Length);
    handshake.CopyTo(record, 5);
    return record;
}

static byte[] MakeFragmentedClientHello(byte[] singleRecordClientHello, int firstFragmentLength)
{
    var handshake = singleRecordClientHello.AsSpan(5);
    True(firstFragmentLength > 0 && firstFragmentLength < handshake.Length);
    var firstRecord = MakeTlsRecord(handshake[..firstFragmentLength]);
    var secondRecord = MakeTlsRecord(handshake[firstFragmentLength..]);
    var result = new byte[firstRecord.Length + secondRecord.Length];
    firstRecord.CopyTo(result, 0);
    secondRecord.CopyTo(result, firstRecord.Length);
    return result;
}

static byte[] MakeTlsRecord(ReadOnlySpan<byte> payload)
{
    var record = new byte[5 + payload.Length];
    record[0] = 0x16;
    record[1] = 0x03;
    record[2] = 0x03;
    BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3, 2), (ushort)payload.Length);
    payload.CopyTo(record.AsSpan(5));
    return record;
}

static byte[] MakeIpv4Packet(byte[] payload, uint sequence)
{
    const int ipLength = 20;
    const int tcpLength = 20;
    var packet = new byte[ipLength + tcpLength + payload.Length];
    packet[0] = 0x45;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), (ushort)packet.Length);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 0x1234);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(6, 2), 0x4000);
    packet[8] = 64;
    packet[9] = 6;
    new byte[] { 10, 0, 0, 2 }.CopyTo(packet, 12);
    new byte[] { 93, 184, 216, 34 }.CopyTo(packet, 16);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLength, 2), 51515);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLength + 2, 2), 443);
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(ipLength + 4, 4), sequence);
    packet[ipLength + 12] = 0x50;
    packet[ipLength + 13] = 0x18; // ACK + PSH
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLength + 14, 2), 4096);
    payload.CopyTo(packet, ipLength + tcpLength);
    return packet;
}

static byte[] MakeIpv6Packet(byte[] payload, uint sequence)
{
    const int ipLength = 40;
    const int tcpLength = 20;
    var packet = new byte[ipLength + tcpLength + payload.Length];
    packet[0] = 0x60;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), (ushort)(tcpLength + payload.Length));
    packet[6] = 6;
    packet[7] = 64;
    for (var i = 0; i < 16; i++)
    {
        packet[8 + i] = (byte)(i + 1);
        packet[24 + i] = (byte)(i + 33);
    }
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLength, 2), 51515);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLength + 2, 2), 443);
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(ipLength + 4, 4), sequence);
    packet[ipLength + 12] = 0x50;
    packet[ipLength + 13] = 0x18;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(ipLength + 14, 2), 4096);
    payload.CopyTo(packet, ipLength + tcpLength);
    return packet;
}

static byte[] MakeIpv6PacketWithOptions(byte[] payload, uint sequence, bool includeHomeAddress = false)
{
    const int ipLength = 40;
    const int hopByHopLength = 8;
    var destinationOptionsLength = includeHomeAddress ? 24 : 8;
    const int tcpLength = 20;
    var tcpOffset = ipLength + hopByHopLength + destinationOptionsLength;
    var packet = new byte[tcpOffset + tcpLength + payload.Length];
    packet[0] = 0x60;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), (ushort)(packet.Length - ipLength));
    packet[6] = 0; // Hop-by-Hop Options
    packet[7] = 64;
    for (var i = 0; i < 16; i++)
    {
        packet[8 + i] = (byte)(i + 1);
        packet[24 + i] = (byte)(i + 33);
    }

    packet[ipLength] = 60; // Destination Options follows Hop-by-Hop Options.
    packet[ipLength + 1] = 0;
    packet[ipLength + 2] = 1; // PadN, length 4.
    packet[ipLength + 3] = 4;

    var destinationOffset = ipLength + hopByHopLength;
    packet[destinationOffset] = 6; // TCP follows Destination Options.
    packet[destinationOffset + 1] = (byte)(destinationOptionsLength / 8 - 1);
    if (includeHomeAddress)
    {
        packet[destinationOffset + 2] = 0xc9;
        packet[destinationOffset + 3] = 16;
        packet[destinationOffset + 20] = 1; // PadN, length 2.
        packet[destinationOffset + 21] = 2;
    }
    else
    {
        packet[destinationOffset + 2] = 1; // PadN, length 4.
        packet[destinationOffset + 3] = 4;
    }

    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcpOffset, 2), 51515);
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcpOffset + 2, 2), 443);
    BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(tcpOffset + 4, 4), sequence);
    packet[tcpOffset + 12] = 0x50;
    packet[tcpOffset + 13] = 0x18;
    BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(tcpOffset + 14, 2), 4096);
    payload.CopyTo(packet, tcpOffset + tcpLength);
    return packet;
}

static void True(bool condition, string description = "condition")
{
    if (!condition)
        throw new InvalidOperationException("Expected true: " + description);
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException($"Expected {expected}, got {actual}.");
}

static void SequenceEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual)
{
    if (!expected.SequenceEqual(actual))
        throw new InvalidOperationException("Byte sequences differ.");
}
