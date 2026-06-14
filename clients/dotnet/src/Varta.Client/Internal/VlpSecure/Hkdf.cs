using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Varta.Internal.VlpSecure;

/// <summary>
/// HKDF-SHA256 derivations for the Varta secure UDP transport. Info
/// strings and IKM/salt direction are pinned by
/// <c>book/src/spec/vlp-secure.md</c> §6 and exercised by
/// <c>tools/vlp-test-vectors.json</c> (categories <c>kdf_agent_key</c>,
/// <c>kdf_iv_prefix</c>, <c>kdf_epoch_key</c>).
/// </summary>
internal static class Hkdf
{
    public const int KeyBytes = 32;
    public const int IvRandomBytes = 8;
    public const int SessionSaltBytes = 16;

    public static void DeriveAgentKey(ReadOnlySpan<byte> masterKey, uint agentId, Span<byte> output32)
    {
        if (masterKey.Length != KeyBytes)
        {
            throw new ArgumentException($"masterKey must be {KeyBytes} bytes", nameof(masterKey));
        }
        if (output32.Length != KeyBytes)
        {
            throw new ArgumentException($"output must be {KeyBytes} bytes", nameof(output32));
        }

        ReadOnlySpan<byte> prefix = "varta-agent-v1\0"u8; // 15 bytes
        Span<byte> info = stackalloc byte[15 + sizeof(uint)];
        prefix.CopyTo(info);
        BinaryPrimitives.WriteUInt32LittleEndian(info[15..], agentId);

        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm: masterKey, output: output32, salt: ReadOnlySpan<byte>.Empty, info: info);
    }

    public static void DeriveIvPrefix(ReadOnlySpan<byte> sessionSalt, uint prefixIndex, Span<byte> output8)
    {
        if (sessionSalt.Length != SessionSaltBytes)
        {
            throw new ArgumentException($"sessionSalt must be {SessionSaltBytes} bytes", nameof(sessionSalt));
        }
        if (output8.Length != IvRandomBytes)
        {
            throw new ArgumentException($"output must be {IvRandomBytes} bytes", nameof(output8));
        }

        ReadOnlySpan<byte> prefix = "varta-iv-prefix-v1\0"u8; // 19 bytes
        Span<byte> info = stackalloc byte[19 + sizeof(uint)];
        prefix.CopyTo(info);
        BinaryPrimitives.WriteUInt32LittleEndian(info[19..], prefixIndex);

        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm: sessionSalt, output: output8, salt: ReadOnlySpan<byte>.Empty, info: info);
    }

    /// <summary>
    /// Derive the 8-byte IV prefix for a secure-UDP panic frame from the
    /// install-time session salt plus the per-fire <c>(panicPid, timestamp,
    /// ivCounter)</c>. All three are authenticated in the sealed frame (pid and
    /// timestamp inside the VLP plaintext, counter in the AEAD nonce), so mixing
    /// the strictly-monotonic timestamp makes every fire's nonce unique across
    /// <c>fork(2)</c> and PID recycling without re-reading OS entropy.
    /// </summary>
    /// <remarks>
    /// Byte-for-byte mirror of <c>crates/varta-vlp/src/crypto/kdf.rs::
    /// derive_panic_iv_prefix</c> and the Go / Python / Node clients. Locked by
    /// the shared KAT (salt = <c>0xA5</c> × 16, pid = 42, ts = 1000, counter = 7)
    /// = <c>e2615ed3e4f44375</c>.
    /// </remarks>
    public static void DerivePanicIvPrefix(
        ReadOnlySpan<byte> sessionSalt,
        uint panicPid,
        ulong timestamp,
        uint ivCounter,
        Span<byte> output8)
    {
        if (sessionSalt.Length != SessionSaltBytes)
        {
            throw new ArgumentException($"sessionSalt must be {SessionSaltBytes} bytes", nameof(sessionSalt));
        }
        if (output8.Length != IvRandomBytes)
        {
            throw new ArgumentException($"output must be {IvRandomBytes} bytes", nameof(output8));
        }

        // info = "varta-panic-iv-v1\0" (18) || panicPid LE32 (4)
        //      || timestamp LE64 (8) || ivCounter LE32 (4) = 34 bytes.
        ReadOnlySpan<byte> prefix = "varta-panic-iv-v1\0"u8; // 18 bytes
        Span<byte> info = stackalloc byte[18 + sizeof(uint) + sizeof(ulong) + sizeof(uint)];
        prefix.CopyTo(info);
        BinaryPrimitives.WriteUInt32LittleEndian(info[18..], panicPid);
        BinaryPrimitives.WriteUInt64LittleEndian(info[22..], timestamp);
        BinaryPrimitives.WriteUInt32LittleEndian(info[30..], ivCounter);

        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm: sessionSalt, output: output8, salt: ReadOnlySpan<byte>.Empty, info: info);
    }

    public static void DeriveEpochKey(ReadOnlySpan<byte> agentKey, ulong epoch, Span<byte> output32)
    {
        if (agentKey.Length != KeyBytes)
        {
            throw new ArgumentException($"agentKey must be {KeyBytes} bytes", nameof(agentKey));
        }
        if (output32.Length != KeyBytes)
        {
            throw new ArgumentException($"output must be {KeyBytes} bytes", nameof(output32));
        }

        ReadOnlySpan<byte> prefix = "varta-epoch-v1\0"u8; // 15 bytes
        Span<byte> info = stackalloc byte[15 + sizeof(ulong)];
        prefix.CopyTo(info);
        BinaryPrimitives.WriteUInt64LittleEndian(info[15..], epoch);

        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm: agentKey, output: output32, salt: ReadOnlySpan<byte>.Empty, info: info);
    }
}
