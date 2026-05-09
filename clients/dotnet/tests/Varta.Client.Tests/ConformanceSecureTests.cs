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
}
