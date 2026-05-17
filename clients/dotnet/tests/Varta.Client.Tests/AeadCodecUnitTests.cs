using System.Security.Cryptography;
using Varta.Internal.VlpSecure;
using Xunit;

namespace Varta.Tests;

public class AeadCodecUnitTests
{
    [Fact]
    public void SharedRoundTrip()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] iv = new byte[AeadCodec.IvRandomBytes];
        RandomNumberGenerator.Fill(iv);
        byte[] pt = new byte[32];
        RandomNumberGenerator.Fill(pt);

        byte[] wire = new byte[AeadCodec.SharedFrameBytes];
        AeadCodec.EncodeShared(key, iv, ivCounter: 7, pt, wire);

        byte[] opened = new byte[32];
        AeadCodec.DecodeShared(key, wire, opened);
        Assert.Equal(pt, opened);
    }

    [Fact]
    public void SharedRejectsTamperedCiphertext()
    {
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] iv = new byte[AeadCodec.IvRandomBytes];
        RandomNumberGenerator.Fill(iv);
        byte[] pt = new byte[32];

        byte[] wire = new byte[AeadCodec.SharedFrameBytes];
        AeadCodec.EncodeShared(key, iv, ivCounter: 0, pt, wire);
        wire[20] ^= 0x01; // flip a ciphertext byte

        byte[] opened = new byte[32];
        Assert.Throws<AuthenticationTagMismatchException>(
            () => AeadCodec.DecodeShared(key, wire, opened));
    }

    [Fact]
    public void MasterRoundTrip()
    {
        byte[] master = new byte[32];
        RandomNumberGenerator.Fill(master);
        byte[] iv = new byte[AeadCodec.IvRandomBytes];
        RandomNumberGenerator.Fill(iv);
        byte[] pt = new byte[32];
        RandomNumberGenerator.Fill(pt);

        byte[] wire = new byte[AeadCodec.MasterFrameBytes];
        byte[] derived = new byte[32];
        AeadCodec.EncodeMaster(master, agentPid: 12345, iv, ivCounter: 0, pt, wire, derived);

        byte[] opened = new byte[32];
        AeadCodec.DecodeMaster(master, wire, opened);
        Assert.Equal(pt, opened);
    }

    [Fact]
    public void MasterTamperedAadFails()
    {
        byte[] master = new byte[32];
        byte[] iv = new byte[AeadCodec.IvRandomBytes];
        byte[] pt = new byte[32];
        byte[] wire = new byte[AeadCodec.MasterFrameBytes];
        byte[] derived = new byte[32];
        AeadCodec.EncodeMaster(master, agentPid: 12345, iv, ivCounter: 0, pt, wire, derived);
        wire[0] ^= 0xFF; // tamper agent_pid AAD

        byte[] opened = new byte[32];
        Assert.Throws<AuthenticationTagMismatchException>(
            () => AeadCodec.DecodeMaster(master, wire, opened));
    }
}
