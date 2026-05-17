using Varta.Internal.Vlp;
using Xunit;

namespace Varta.Tests;

public class VlpCodecUnitTests
{
    [Fact]
    public void EncodeDecodeRoundTrip_Ok()
    {
        byte[] buf = new byte[Frame.Bytes];
        Codec.EncodeInto(buf, Status.Ok, pid: 12345, timestamp: 999_999_000, nonce: 7, payload: 42);
        var f = Frame.Decode(buf);
        Assert.Equal(Status.Ok, f.Status);
        Assert.Equal(12345u, f.Pid);
        Assert.Equal(999_999_000ul, f.Timestamp);
        Assert.Equal(7ul, f.Nonce);
        Assert.Equal(42u, f.Payload);
    }

    [Fact]
    public void CriticalWithNonceTerminalRoundTrips()
    {
        byte[] buf = new byte[Frame.Bytes];
        Codec.EncodeInto(buf, Status.Critical, pid: 12345, timestamp: 1, nonce: Frame.NonceTerminal, payload: 0);
        var f = Frame.Decode(buf);
        Assert.Equal(Status.Critical, f.Status);
        Assert.Equal(Frame.NonceTerminal, f.Nonce);
    }

    [Fact]
    public void RejectBadMagic()
    {
        byte[] buf = MakeValid();
        buf[0] = 0x00;
        StampCrc(buf);
        Assert.Equal(DecodeErrorKind.BadMagic, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    [Fact]
    public void RejectBadVersion()
    {
        byte[] buf = MakeValid();
        buf[2] = 0x99;
        StampCrc(buf);
        Assert.Equal(DecodeErrorKind.BadVersion, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    [Fact]
    public void RejectBadCrc()
    {
        byte[] buf = MakeValid();
        buf[31] ^= 0xFF; // flip trailer
        Assert.Equal(DecodeErrorKind.BadCrc, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    [Fact]
    public void RejectBadStatus()
    {
        byte[] buf = MakeValid();
        buf[3] = 0xAA;
        StampCrc(buf);
        Assert.Equal(DecodeErrorKind.BadStatus, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    [Fact]
    public void RejectStallOnWire()
    {
        byte[] buf = MakeValid();
        buf[3] = 0x03;
        StampCrc(buf);
        Assert.Equal(DecodeErrorKind.StallOnWire, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    [Theory]
    [InlineData(0u)]
    [InlineData(1u)]
    public void RejectBadPid(uint badPid)
    {
        byte[] buf = MakeValid();
        Span<byte> span = buf.AsSpan();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(4, 4), badPid);
        StampCrc(buf);
        Assert.Equal(DecodeErrorKind.BadPid, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    [Fact]
    public void RejectBadTimestamp()
    {
        byte[] buf = MakeValid();
        Span<byte> span = buf.AsSpan();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(span.Slice(8, 8), ulong.MaxValue);
        StampCrc(buf);
        Assert.Equal(DecodeErrorKind.BadTimestamp, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    [Fact]
    public void RejectBadNonceTerminalWithNonCritical()
    {
        byte[] buf = new byte[Frame.Bytes];
        Codec.EncodeInto(buf, Status.Ok, pid: 12345, timestamp: 1, nonce: Frame.NonceTerminal, payload: 0);
        Assert.Equal(DecodeErrorKind.BadNonce, Assert.Throws<DecodeError>(() => Frame.Decode(buf)).Kind);
    }

    private static byte[] MakeValid()
    {
        byte[] buf = new byte[Frame.Bytes];
        Codec.EncodeInto(buf, Status.Ok, pid: 1234, timestamp: 555, nonce: 9, payload: 1);
        return buf;
    }

    private static void StampCrc(byte[] buf)
    {
        uint crc = Crc32C.Compute(buf.AsSpan(0, 28));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(28, 4), crc);
    }
}
