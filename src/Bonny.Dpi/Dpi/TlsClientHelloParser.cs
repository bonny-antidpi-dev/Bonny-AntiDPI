using System.Buffers;
using System.Text;

namespace Bonny.Dpi;

internal enum ClientHelloParseStatus
{
    NeedMoreData,
    NotClientHello,
    ClientHelloWithoutSni,
    ClientHelloWithSni,
    Malformed
}

internal readonly record struct ClientHelloInfo(string Host, int SniHostOffset, int MessageLength);

internal static class TlsClientHelloParser
{
    private const int TlsRecordHeaderLength = 5;
    private const int HandshakeHeaderLength = 4;
    private const int MaximumTlsRecordLength = 18_432;
    private const int MaximumClientHelloLength = 32 * 1024;

    public static ClientHelloParseStatus Parse(ReadOnlySpan<byte> stream, out ClientHelloInfo info)
    {
        info = default;
        if (stream.Length < TlsRecordHeaderLength)
            return ClientHelloParseStatus.NeedMoreData;

        if (!IsHandshakeRecordHeader(stream))
            return ClientHelloParseStatus.NotClientHello;

        var handshakeBuffer = ArrayPool<byte>.Shared.Rent(MaximumClientHelloLength);
        try
        {
            var handshakeBytes = 0;
            var handshakeLength = -1;
            var streamOffset = 0;

            while (handshakeLength < 0 || handshakeBytes < HandshakeHeaderLength + handshakeLength)
            {
                if (stream.Length - streamOffset < TlsRecordHeaderLength)
                    return ClientHelloParseStatus.NeedMoreData;
                if (!IsHandshakeRecordHeader(stream.Slice(streamOffset)))
                    return ClientHelloParseStatus.Malformed;

                var recordLength = ReadUInt16(stream, streamOffset + 3);
                if (recordLength == 0 || recordLength > MaximumTlsRecordLength)
                    return ClientHelloParseStatus.Malformed;
                if (stream.Length - streamOffset - TlsRecordHeaderLength < recordLength)
                    return ClientHelloParseStatus.NeedMoreData;

                var bytesToCopy = Math.Min(recordLength, MaximumClientHelloLength - handshakeBytes);
                if (bytesToCopy <= 0)
                    return ClientHelloParseStatus.Malformed;
                stream.Slice(streamOffset + TlsRecordHeaderLength, bytesToCopy)
                    .CopyTo(handshakeBuffer.AsSpan(handshakeBytes));
                handshakeBytes += bytesToCopy;
                streamOffset += TlsRecordHeaderLength + recordLength;

                if (handshakeBytes >= 1 && handshakeBuffer[0] != 0x01)
                    return ClientHelloParseStatus.NotClientHello;
                if (handshakeBytes >= HandshakeHeaderLength && handshakeLength < 0)
                {
                    handshakeLength = ReadUInt24(handshakeBuffer, 1);
                    if (handshakeLength == 0 || HandshakeHeaderLength + handshakeLength > MaximumClientHelloLength)
                        return ClientHelloParseStatus.Malformed;
                }
            }

            var targetLength = HandshakeHeaderLength + handshakeLength;
            var parseStatus = ParseClientHello(handshakeBuffer.AsSpan(0, targetLength), out var host, out var logicalHostOffset);
            if (parseStatus != ClientHelloParseStatus.ClientHelloWithSni)
                return parseStatus;

            if (!TryMapHandshakeOffsets(stream, targetLength, logicalHostOffset, out var hostOffset, out var messageEnd))
                return ClientHelloParseStatus.Malformed;

            info = new ClientHelloInfo(host, hostOffset, messageEnd);
            return ClientHelloParseStatus.ClientHelloWithSni;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(handshakeBuffer, clearArray: true);
        }
    }

    private static ClientHelloParseStatus ParseClientHello(
        ReadOnlySpan<byte> handshake,
        out string host,
        out int hostOffset)
    {
        host = string.Empty;
        hostOffset = -1;
        if (handshake.Length < HandshakeHeaderLength || handshake[0] != 0x01)
            return ClientHelloParseStatus.NotClientHello;

        var handshakeLength = ReadUInt24(handshake, 1);
        var bodyEnd = HandshakeHeaderLength + handshakeLength;
        if (bodyEnd != handshake.Length)
            return ClientHelloParseStatus.Malformed;

        var cursor = HandshakeHeaderLength;
        // legacy_version + random
        if (!Has(cursor, 34, bodyEnd))
            return ClientHelloParseStatus.Malformed;
        cursor += 34;

        if (!Has(cursor, 1, bodyEnd))
            return ClientHelloParseStatus.Malformed;
        var sessionIdLength = handshake[cursor++];
        if (!Has(cursor, sessionIdLength, bodyEnd))
            return ClientHelloParseStatus.Malformed;
        cursor += sessionIdLength;

        if (!Has(cursor, 2, bodyEnd))
            return ClientHelloParseStatus.Malformed;
        var cipherSuitesLength = ReadUInt16(handshake, cursor);
        cursor += 2;
        if (cipherSuitesLength == 0 || (cipherSuitesLength & 1) != 0 || !Has(cursor, cipherSuitesLength, bodyEnd))
            return ClientHelloParseStatus.Malformed;
        cursor += cipherSuitesLength;

        if (!Has(cursor, 1, bodyEnd))
            return ClientHelloParseStatus.Malformed;
        var compressionLength = handshake[cursor++];
        if (!Has(cursor, compressionLength, bodyEnd))
            return ClientHelloParseStatus.Malformed;
        cursor += compressionLength;

        if (cursor == bodyEnd)
            return ClientHelloParseStatus.ClientHelloWithoutSni;
        if (!Has(cursor, 2, bodyEnd))
            return ClientHelloParseStatus.Malformed;

        var extensionsLength = ReadUInt16(handshake, cursor);
        cursor += 2;
        var extensionsEnd = cursor + extensionsLength;
        if (extensionsEnd != bodyEnd)
            return ClientHelloParseStatus.Malformed;

        while (cursor < extensionsEnd)
        {
            if (!Has(cursor, 4, extensionsEnd))
                return ClientHelloParseStatus.Malformed;
            var extensionType = ReadUInt16(handshake, cursor);
            var extensionLength = ReadUInt16(handshake, cursor + 2);
            cursor += 4;
            var extensionEnd = cursor + extensionLength;
            if (extensionEnd > extensionsEnd)
                return ClientHelloParseStatus.Malformed;

            if (extensionType == 0x0000)
            {
                var sniStatus = TryReadSni(handshake, cursor, extensionEnd, out host, out hostOffset);
                return sniStatus;
            }

            cursor = extensionEnd;
        }

        return ClientHelloParseStatus.ClientHelloWithoutSni;
    }

    private static ClientHelloParseStatus TryReadSni(
        ReadOnlySpan<byte> handshake,
        int start,
        int end,
        out string host,
        out int hostOffset)
    {
        host = string.Empty;
        hostOffset = -1;
        if (end - start < 2)
            return ClientHelloParseStatus.Malformed;

        var listLength = ReadUInt16(handshake, start);
        var cursor = start + 2;
        var listEnd = cursor + listLength;
        if (listEnd != end)
            return ClientHelloParseStatus.Malformed;

        while (cursor < listEnd)
        {
            if (!Has(cursor, 3, listEnd))
                return ClientHelloParseStatus.Malformed;
            var nameType = handshake[cursor++];
            var nameLength = ReadUInt16(handshake, cursor);
            cursor += 2;
            if (nameLength == 0 || !Has(cursor, nameLength, listEnd))
                return ClientHelloParseStatus.Malformed;

            if (nameType == 0)
            {
                for (var i = cursor; i < cursor + nameLength; i++)
                {
                    if (handshake[i] is < 0x21 or > 0x7e)
                        return ClientHelloParseStatus.Malformed;
                }

                host = Encoding.ASCII.GetString(handshake.Slice(cursor, nameLength)).TrimEnd('.');
                hostOffset = cursor;
                return host.Length > 0
                    ? ClientHelloParseStatus.ClientHelloWithSni
                    : ClientHelloParseStatus.Malformed;
            }

            cursor += nameLength;
        }

        return ClientHelloParseStatus.ClientHelloWithoutSni;
    }

    private static bool TryMapHandshakeOffsets(
        ReadOnlySpan<byte> stream,
        int handshakeLength,
        int logicalHostOffset,
        out int streamHostOffset,
        out int streamMessageEnd)
    {
        streamHostOffset = -1;
        streamMessageEnd = -1;
        var streamOffset = 0;
        var logicalOffset = 0;

        while (logicalOffset < handshakeLength)
        {
            if (stream.Length - streamOffset < TlsRecordHeaderLength || !IsHandshakeRecordHeader(stream.Slice(streamOffset)))
                return false;

            var recordLength = ReadUInt16(stream, streamOffset + 3);
            if (recordLength == 0 || recordLength > MaximumTlsRecordLength ||
                stream.Length - streamOffset - TlsRecordHeaderLength < recordLength)
                return false;

            var copied = Math.Min(recordLength, handshakeLength - logicalOffset);
            if (logicalHostOffset >= logicalOffset && logicalHostOffset < logicalOffset + copied)
                streamHostOffset = streamOffset + TlsRecordHeaderLength + logicalHostOffset - logicalOffset;

            logicalOffset += copied;
            if (logicalOffset == handshakeLength)
            {
                streamMessageEnd = streamOffset + TlsRecordHeaderLength + copied;
                break;
            }

            streamOffset += TlsRecordHeaderLength + recordLength;
        }

        return streamHostOffset >= 0 && streamMessageEnd >= 0;
    }

    private static bool IsHandshakeRecordHeader(ReadOnlySpan<byte> data) =>
        data.Length >= TlsRecordHeaderLength && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04;

    private static bool Has(int offset, int length, int end) =>
        offset >= 0 && length >= 0 && offset <= end && length <= end - offset;

    private static int ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
        (data[offset] << 8) | data[offset + 1];

    private static int ReadUInt24(ReadOnlySpan<byte> data, int offset) =>
        (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
}
