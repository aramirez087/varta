using System.Linq;
using Varta.Internal.VlpSecure;
using Varta.Tests.Helpers;
using Xunit;

namespace Varta.Tests;

public class ConformanceSecureTests
{
    public static IEnumerable<object[]> AllVectors() => Vectors.AsTheoryData(Vectors.Secure());

    [Theory]
    [MemberData(nameof(AllVectors))]
    public void MatchesGoldenVector(string id, VectorRow row)
    {
        var v = row.Element;
        string kind = v.GetProperty("kind").GetString()!;

        switch (kind)
        {
            case "shared_key_seal":
                CheckSharedKeySeal(v); break;
            case "master_key_seal":
                CheckMasterKeySeal(v); break;
            case "kdf_agent_key":
                CheckKdfAgentKey(v); break;
            case "kdf_iv_prefix":
                CheckKdfIvPrefix(v); break;
            case "kdf_epoch_key":
                CheckKdfEpochKey(v); break;
            default:
                throw new InvalidOperationException($"unknown secure vector kind '{kind}'");
        }
    }

    private static void CheckSharedKeySeal(System.Text.Json.JsonElement v)
    {
        byte[] key = Vectors.Hex(v.GetProperty("key_hex").GetString()!);
        byte[] iv = Vectors.Hex(v.GetProperty("iv_random_hex").GetString()!);
        uint counter = v.GetProperty("iv_counter").GetUInt32();
        byte[] plaintext = Vectors.Hex(v.GetProperty("plaintext_hex").GetString()!);
        byte[] expected = Vectors.Hex(v.GetProperty("expected_wire_hex").GetString()!);

        byte[] actual = new byte[AeadCodec.SharedFrameBytes];
        AeadCodec.EncodeShared(key, iv, counter, plaintext, actual);
        Assert.Equal(expected, actual);

        byte[] opened = new byte[AeadCodec.PlaintextBytes];
        AeadCodec.DecodeShared(key, actual, opened);
        Assert.Equal(plaintext, opened);
    }

    private static void CheckMasterKeySeal(System.Text.Json.JsonElement v)
    {
        byte[] master = Vectors.Hex(v.GetProperty("master_key_hex").GetString()!);
        uint pid = v.GetProperty("agent_pid").GetUInt32();
        byte[] iv = Vectors.Hex(v.GetProperty("iv_random_hex").GetString()!);
        uint counter = v.GetProperty("iv_counter").GetUInt32();
        byte[] plaintext = Vectors.Hex(v.GetProperty("plaintext_hex").GetString()!);
        byte[] expectedWire = Vectors.Hex(v.GetProperty("expected_wire_hex").GetString()!);
        byte[] expectedDerived = Vectors.Hex(v.GetProperty("derived_agent_key_hex").GetString()!);

        byte[] actualWire = new byte[AeadCodec.MasterFrameBytes];
        byte[] derived = new byte[Hkdf.KeyBytes];
        AeadCodec.EncodeMaster(master, pid, iv, counter, plaintext, actualWire, derived);
        Assert.Equal(expectedDerived, derived);
        Assert.Equal(expectedWire, actualWire);

        byte[] opened = new byte[AeadCodec.PlaintextBytes];
        AeadCodec.DecodeMaster(master, actualWire, opened);
        Assert.Equal(plaintext, opened);
    }

    private static void CheckKdfAgentKey(System.Text.Json.JsonElement v)
    {
        byte[] master = Vectors.Hex(v.GetProperty("master_key_hex").GetString()!);
        uint agentId = v.GetProperty("agent_id").GetUInt32();
        byte[] expected = Vectors.Hex(v.GetProperty("expected_okm_hex").GetString()!);

        byte[] actual = new byte[Hkdf.KeyBytes];
        Hkdf.DeriveAgentKey(master, agentId, actual);
        Assert.Equal(expected, actual);
    }

    private static void CheckKdfIvPrefix(System.Text.Json.JsonElement v)
    {
        byte[] salt = Vectors.Hex(v.GetProperty("session_salt_hex").GetString()!);
        uint prefixIndex = v.GetProperty("prefix_index").GetUInt32();
        byte[] expected = Vectors.Hex(v.GetProperty("expected_iv_prefix_hex").GetString()!);

        byte[] actual = new byte[Hkdf.IvRandomBytes];
        Hkdf.DeriveIvPrefix(salt, prefixIndex, actual);
        Assert.Equal(expected, actual);
    }

    private static void CheckKdfEpochKey(System.Text.Json.JsonElement v)
    {
        byte[] agentKey = Vectors.Hex(v.GetProperty("agent_key_hex").GetString()!);
        ulong epoch = v.GetProperty("epoch").GetUInt64();
        byte[] expected = Vectors.Hex(v.GetProperty("expected_okm_hex").GetString()!);

        byte[] actual = new byte[Hkdf.KeyBytes];
        Hkdf.DeriveEpochKey(agentKey, epoch, actual);
        Assert.Equal(expected, actual);
    }

    private static byte[] PanicIv(byte[] salt, uint pid, ulong ts, uint ctr)
    {
        byte[] o = new byte[Hkdf.IvRandomBytes];
        Hkdf.DerivePanicIvPrefix(salt, pid, ts, ctr, o);
        return o;
    }

    /// Shared known-answer test locking the panic-IV KDF byte-for-byte across
    /// the Rust / Go / Python / Node / .NET clients. salt = 0xA5 x 16,
    /// pid = 42, ts = 1000, counter = 7 must derive e2615ed3e4f44375, and each
    /// input must independently change the prefix.
    [Fact]
    public void DerivePanicIvPrefix_MatchesCrossClientKat()
    {
        byte[] saltA5 = Enumerable.Repeat((byte)0xA5, Hkdf.SessionSaltBytes).ToArray();

        byte[] kat = PanicIv(saltA5, 42, 1000, 7);
        Assert.Equal("e2615ed3e4f44375", Convert.ToHexString(kat).ToLowerInvariant());

        // Deterministic.
        Assert.Equal(kat, PanicIv(saltA5, 42, 1000, 7));

        // Each input independently perturbs the output.
        Assert.NotEqual(kat, PanicIv(saltA5, 43, 1000, 7)); // pid
        Assert.NotEqual(kat, PanicIv(saltA5, 42, 1001, 7)); // timestamp
        Assert.NotEqual(kat, PanicIv(saltA5, 42, 1000, 8)); // counter
    }

    /// A descendant reassigned the installer's exact PID at counter 0 must
    /// still derive a disjoint prefix, because the monotonic timestamp differs.
    /// This is the PID-recycle nonce-reuse invariant (bug-446) the .NET client
    /// previously lacked.
    [Fact]
    public void DerivePanicIvPrefix_PidRecycleWithLaterTimestampIsDisjoint()
    {
        byte[] salt = Enumerable.Repeat((byte)0x5A, Hkdf.SessionSaltBytes).ToArray();
        byte[] installer = PanicIv(salt, 4242, 1000, 0);
        byte[] recycled = PanicIv(salt, 4242, 9_999_000, 0);
        Assert.NotEqual(installer, recycled);
    }
}
