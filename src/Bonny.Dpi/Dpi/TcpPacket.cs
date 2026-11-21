namespace Bonny.Dpi;

internal readonly record struct TcpPacketInfo(
    int IpVersion,
    int IpHeaderLength,
    int TcpOffset,
    int TcpHeaderLength,
    int PayloadOffset,
    int PayloadLength,
    int PacketLength,
    uint SequenceNumber,
    byte TcpFlags,
    string FlowKey)
{
    public static bool TryParse(ReadOnlySpan<byte> packet, out TcpPacketInfo info)
    {
        info = default;
        if (packet.Length < 40)
            return false;

        var version = packet[0] >> 4;
        int ipHeaderLength;
        int packetLength;
        var tcpOffset = 0;
        string source;
        string destination;

        if (version == 4)
        {
            ipHeaderLength = (packet[0] & 0x0f) * 4;
            if (ipHeaderLength < 20 || packet.Length < ipHeaderLength + 20 || packet[9] != 6)
                return false;

            packetLength = ReadUInt16(packet, 2);
            if (packetLength < ipHeaderLength + 20 || packetLength > packet.Length)
                return false;

            // Do not edit IP-fragmented packets.
            var fragment = ReadUInt16(packet, 6);
            if ((fragment & 0x3fff) != 0)
                return false;

            source = Convert.ToHexString(packet.Slice(12, 4));
            destination = Convert.ToHexString(packet.Slice(16, 4));
            tcpOffset = ipHeaderLength;
        }
        else if (version == 6)
        {
            ipHeaderLength = 40;
            if (packet.Length < 60)
                return false;

            packetLength = ipHeaderLength + ReadUInt16(packet, 4);
            if (packetLength < ipHeaderLength + 20 || packetLength > packet.Length)
                return false;

            source = Convert.ToHexString(packet.Slice(8, 16));
            destination = Convert.ToHexString(packet.Slice(24, 16));
            tcpOffset = ipHeaderLength;

            var nextHeader = packet[6];
            var extensionCount = 0;
            while (nextHeader != 6)
            {
                if (++extensionCount > 16 || nextHeader is not (0 or 60) ||
                    tcpOffset + 2 > packetLength)
                    return false; // Routing, fragment, AH/ESP, and unknown headers stay untouched.

                var followingHeader = packet[tcpOffset];
                var extensionLength = (packet[tcpOffset + 1] + 1) * 8;
                if (tcpOffset + extensionLength > packetLength ||
                    !HasSafeIpv6Options(packet, tcpOffset, extensionLength))
                    return false;

                tcpOffset += extensionLength;
                nextHeader = followingHeader;
            }
        }
        else
        {
            return false;
        }

        if (tcpOffset + 20 > packetLength)
            return false;

        var tcpHeaderLength = (packet[tcpOffset + 12] >> 4) * 4;
        if (tcpHeaderLength < 20 || tcpOffset + tcpHeaderLength > packetLength)
            return false;

        var payloadOffset = tcpOffset + tcpHeaderLength;
        var payloadLength = packetLength - payloadOffset;
        if (payloadLength <= 0)
            return false;

        var sourcePort = ReadUInt16(packet, tcpOffset);
        var destinationPort = ReadUInt16(packet, tcpOffset + 2);
        var sequence = ReadUInt32(packet, tcpOffset + 4);
        var flags = packet[tcpOffset + 13];
        var flow = $"{version}:{source}:{sourcePort}>{destination}:{destinationPort}";
        info = new TcpPacketInfo(version, ipHeaderLength, tcpOffset, tcpHeaderLength,
            payloadOffset, payloadLength, packetLength, sequence, flags, flow);
        return true;
    }

    private static bool HasSafeIpv6Options(ReadOnlySpan<byte> packet, int offset, int headerLength)
    {
        var cursor = offset + 2;
        var end = offset + headerLength;
        while (cursor < end)
        {
            var optionType = packet[cursor++];
            if (optionType == 0) // Pad1
                continue;

            if (cursor >= end)
                return false;

            var optionLength = packet[cursor++];
            if (optionLength > end - cursor || optionType == 0xc9) // Home Address changes the TCP pseudo-header.
                return false;
            cursor += optionLength;
        }

        return cursor == end;
    }

    public static bool TrySplit(byte[] packet, int splitAtPayloadOffset, out byte[] first, out byte[] second)
    {
        first = Array.Empty<byte>();
        second = Array.Empty<byte>();
        if (!TryParse(packet, out var info) ||
            splitAtPayloadOffset <= 0 || splitAtPayloadOffset >= info.PayloadLength ||
            (info.TcpFlags & 0x02) != 0) // SYN-data/TFO packets are never rewritten.
            return false;

        var firstLength = info.PayloadOffset + splitAtPayloadOffset;
        var secondPayloadLength = info.PayloadLength - splitAtPayloadOffset;
        var secondLength = info.PayloadOffset + secondPayloadLength;
        first = packet.AsSpan(0, firstLength).ToArray();
        second = new byte[secondLength];
        packet.AsSpan(0, info.PayloadOffset).CopyTo(second);
        packet.AsSpan(info.PayloadOffset + splitAtPayloadOffset, secondPayloadLength)
            .CopyTo(second.AsSpan(info.PayloadOffset));

        UpdatePacketLengths(first, info.IpVersion, info.IpHeaderLength);
        UpdatePacketLengths(second, info.IpVersion, info.IpHeaderLength);

        // The second segment continues at the first segment's final TCP sequence.
        WriteUInt32(second, info.TcpOffset + 4, unchecked(info.SequenceNumber + (uint)splitAtPayloadOffset));
        if (info.IpVersion == 4)
            WriteUInt16(second, 4, unchecked((ushort)(ReadUInt16(packet, 4) + 1)));
        first[info.TcpOffset + 13] = (byte)(first[info.TcpOffset + 13] & ~(0x01 | 0x08)); // FIN/PSH belong on tail.

        RecalculateChecksums(first, info.IpVersion, info.IpHeaderLength, info.TcpOffset);
        RecalculateChecksums(second, info.IpVersion, info.IpHeaderLength, info.TcpOffset);
        return true;
    }

    private static void UpdatePacketLengths(byte[] packet, int ipVersion, int ipHeaderLength)
    {
        if (ipVersion == 4)
            WriteUInt16(packet, 2, packet.Length);
        else
            WriteUInt16(packet, 4, packet.Length - ipHeaderLength);
    }

    private static void RecalculateChecksums(byte[] packet, int ipVersion, int ipHeaderLength, int tcpOffset)
    {
        if (ipVersion == 4)
        {
            WriteUInt16(packet, 10, 0);
            WriteUInt16(packet, 10, ComputeChecksum(packet.AsSpan(0, ipHeaderLength)));
        }

        var tcpLength = packet.Length - tcpOffset;
        WriteUInt16(packet, tcpOffset + 16, 0);
        ulong sum = 0;
        if (ipVersion == 4)
        {
            sum = SumWords(packet.AsSpan(12, 8), sum);
            sum += 6;
            sum += (uint)tcpLength;
        }
        else
        {
            sum = SumWords(packet.AsSpan(8, 32), sum);
            sum += (uint)(tcpLength >> 16);
            sum += (uint)(tcpLength & 0xffff);
            sum += 6;
        }

        sum = SumWords(packet.AsSpan(tcpOffset, tcpLength), sum);
        WriteUInt16(packet, tcpOffset + 16, FoldChecksum(sum));
    }

    private static ushort ComputeChecksum(ReadOnlySpan<byte> bytes) => FoldChecksum(SumWords(bytes, 0));

    private static ulong SumWords(ReadOnlySpan<byte> bytes, ulong sum)
    {
        var i = 0;
        for (; i + 1 < bytes.Length; i += 2)
            sum += (uint)((bytes[i] << 8) | bytes[i + 1]);
        if (i < bytes.Length)
            sum += (uint)(bytes[i] << 8);
        return sum;
    }

    private static ushort FoldChecksum(ulong sum)
    {
        while ((sum >> 16) != 0)
            sum = (sum & 0xffff) + (sum >> 16);
        var result = (ushort)~sum;
        return result == 0 ? (ushort)0xffff : result;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16) |
        ((uint)data[offset + 2] << 8) | data[offset + 3];

    private static void WriteUInt16(byte[] data, int offset, int value)
    {
        data[offset] = (byte)(value >> 8);
        data[offset + 1] = (byte)value;
    }

    private static void WriteUInt32(byte[] data, int offset, uint value)
    {
        data[offset] = (byte)(value >> 24);
        data[offset + 1] = (byte)(value >> 16);
        data[offset + 2] = (byte)(value >> 8);
        data[offset + 3] = (byte)value;
    }
}
