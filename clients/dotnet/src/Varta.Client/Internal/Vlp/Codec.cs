using System.Buffers.Binary;

namespace Varta.Internal.Vlp;

/// <summary>
/// VLP v0.2 base frame wire codec — 32 bytes, little-endian, CRC-32C
/// trailer. Spec: <c>book/src/spec/vlp.md</c>.
/// </summary>
internal static class Codec
{
    public const int FrameBytes = Frame.Bytes;

    private const byte MagicByte0 = 0x56; // 'V'
    private const byte MagicByte1 = 0x41; // 'A'
    private const byte WireVersion = 0x02;

    private const int OffsetMagic = 0;
    private const int OffsetVersion = 2;
    private const int OffsetStatus = 3;
    private const int OffsetPid = 4;
    private const int OffsetTimestamp = 8;
    private const int OffsetNonce = 16;
    private const int OffsetPayload = 24;
    private const int OffsetCrc = 28;
    private const int CrcCoverageLen = 28; // bytes 0..28

    public const byte StatusOkWire = 0x00;
    public const byte StatusDegradedWire = 0x01;
    public const byte StatusCriticalWire = 0x02;
    public const byte StatusStallWire = 0x03;

    /// <summary>
    /// Encode a frame into <paramref name="dest"/>. <paramref name="dest"/>
    /// must be exactly <see cref="FrameBytes"/> long.
    /// </summary>
    public static void EncodeInto(Span<byte> dest, Status status, uint pid, ulong timestamp, ulong nonce, uint payload)
    {
        if (dest.Length != FrameBytes)
        {
            throw new ArgumentException($"destination must be {FrameBytes} bytes", nameof(dest));
        }

        dest[OffsetMagic] = MagicByte0;
        dest[OffsetMagic + 1] = MagicByte1;
        dest[OffsetVersion] = WireVersion;
        dest[OffsetStatus] = (byte)status;
        BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(OffsetPid, 4), pid);
        BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(OffsetTimestamp, 8), timestamp);
        BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(OffsetNonce, 8), nonce);
        BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(OffsetPayload, 4), payload);

        uint crc = Crc32C.Compute(dest[..CrcCoverageLen]);
        BinaryPrimitives.WriteUInt32LittleEndian(dest.Slice(OffsetCrc, 4), crc);
    }

    public static Frame Decode(ReadOnlySpan<byte> wire)
    {
        if (wire.Length != FrameBytes)
        {
            throw new DecodeError(DecodeErrorKind.BadMagic, $"wire length {wire.Length} != {FrameBytes}");
        }
        if (wire[OffsetMagic] != MagicByte0 || wire[OffsetMagic + 1] != MagicByte1)
        {
            throw new DecodeError(DecodeErrorKind.BadMagic, $"magic 0x{wire[OffsetMagic]:X2}{wire[OffsetMagic + 1]:X2} != 0x5641");
        }
        if (wire[OffsetVersion] != WireVersion)
        {
            throw new DecodeError(DecodeErrorKind.BadVersion, $"version 0x{wire[OffsetVersion]:X2} != 0x{WireVersion:X2}");
        }

        uint actual = BinaryPrimitives.ReadUInt32LittleEndian(wire.Slice(OffsetCrc, 4));
        uint expected = Crc32C.Compute(wire[..CrcCoverageLen]);
        if (actual != expected)
        {
            throw new DecodeError(DecodeErrorKind.BadCrc, $"expected 0x{expected:X8} actual 0x{actual:X8}");
        }

        byte statusByte = wire[OffsetStatus];
        Status status;
        switch (statusByte)
        {
            case StatusOkWire: status = Status.Ok; break;
            case StatusDegradedWire: status = Status.Degraded; break;
            case StatusCriticalWire: status = Status.Critical; break;
            case StatusStallWire:
                throw new DecodeError(DecodeErrorKind.StallOnWire, "Status.Stall is observer-synthesised and forbidden on the wire");
            default:
                throw new DecodeError(DecodeErrorKind.BadStatus, $"unknown status 0x{statusByte:X2}");
        }

        uint pid = BinaryPrimitives.ReadUInt32LittleEndian(wire.Slice(OffsetPid, 4));
        if (pid == 0 || pid == 1)
        {
            throw new DecodeError(DecodeErrorKind.BadPid, $"pid {pid} is reserved");
        }

        ulong timestamp = BinaryPrimitives.ReadUInt64LittleEndian(wire.Slice(OffsetTimestamp, 8));
        if (timestamp == ulong.MaxValue)
        {
            throw new DecodeError(DecodeErrorKind.BadTimestamp, "timestamp is u64::MAX sentinel");
        }

        ulong nonce = BinaryPrimitives.ReadUInt64LittleEndian(wire.Slice(OffsetNonce, 8));
        if (nonce == Frame.NonceTerminal && status != Status.Critical)
        {
            throw new DecodeError(DecodeErrorKind.BadNonce, "NONCE_TERMINAL is only legal paired with Status.Critical");
        }

        uint payload = BinaryPrimitives.ReadUInt32LittleEndian(wire.Slice(OffsetPayload, 4));
        return new Frame(status, pid, timestamp, nonce, payload);
    }
}
