using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Varta.Internal.VlpSecure;

/// <summary>
/// ChaCha20-Poly1305 wire codec for the Varta secure UDP transport.
/// Two modes:
/// <list type="bullet">
///   <item><c>Shared</c> — 32-byte pre-shared key, 60-byte wire frame.</item>
///   <item><c>Master</c> — 32-byte master key + per-agent key derived
///     via HKDF (agent_pid as info); 64-byte wire frame with agent_pid
///     as AAD.</item>
/// </list>
/// Spec: <c>book/src/spec/vlp-secure.md</c>. Conformance vectors:
/// <c>tools/vlp-test-vectors.json</c> under <c>secure_frame_vectors</c>.
/// </summary>
internal static class AeadCodec
{
    public const int KeyBytes = 32;
    public const int IvRandomBytes = 8;
    public const int IvCounterBytes = 4;
    public const int AeadNonceBytes = 12;
    public const int TagBytes = 16;
    public const int PlaintextBytes = 32;
    public const int SharedFrameBytes = 60; // iv_random[8] + iv_counter[4] + ct[32] + tag[16]
    public const int MasterFrameBytes = 64; // agent_pid[4] + iv_random[8] + iv_counter[4] + ct[32] + tag[16]
    public const int AgentPidBytes = 4;

    public static void EncodeShared(
        ReadOnlySpan<byte> key32,
        ReadOnlySpan<byte> ivRandom8,
        uint ivCounter,
        ReadOnlySpan<byte> plaintext32,
        Span<byte> destination60)
    {
        if (key32.Length != KeyBytes) throw new ArgumentException("key must be 32 bytes", nameof(key32));
        if (ivRandom8.Length != IvRandomBytes) throw new ArgumentException("ivRandom must be 8 bytes", nameof(ivRandom8));
        if (plaintext32.Length != PlaintextBytes) throw new ArgumentException("plaintext must be 32 bytes", nameof(plaintext32));
        if (destination60.Length != SharedFrameBytes) throw new ArgumentException($"destination must be {SharedFrameBytes} bytes", nameof(destination60));

        Span<byte> nonce = stackalloc byte[AeadNonceBytes];
        ivRandom8.CopyTo(nonce);
        BinaryPrimitives.WriteUInt32LittleEndian(nonce[IvRandomBytes..], ivCounter);

        ivRandom8.CopyTo(destination60[..IvRandomBytes]);
        BinaryPrimitives.WriteUInt32LittleEndian(destination60.Slice(IvRandomBytes, IvCounterBytes), ivCounter);

        Span<byte> ciphertext = destination60.Slice(IvRandomBytes + IvCounterBytes, PlaintextBytes);
        Span<byte> tag = destination60.Slice(IvRandomBytes + IvCounterBytes + PlaintextBytes, TagBytes);

        using var aead = new ChaCha20Poly1305(key32);
        aead.Encrypt(nonce, plaintext32, ciphertext, tag, associatedData: ReadOnlySpan<byte>.Empty);
    }

    public static void DecodeShared(ReadOnlySpan<byte> key32, ReadOnlySpan<byte> wire60, Span<byte> plaintext32)
    {
        if (key32.Length != KeyBytes) throw new ArgumentException("key must be 32 bytes", nameof(key32));
        if (wire60.Length != SharedFrameBytes) throw new ArgumentException($"wire must be {SharedFrameBytes} bytes", nameof(wire60));
        if (plaintext32.Length != PlaintextBytes) throw new ArgumentException($"plaintext must be {PlaintextBytes} bytes", nameof(plaintext32));

        ReadOnlySpan<byte> nonce = wire60[..AeadNonceBytes]; // iv_random[8] || iv_counter[4]
        ReadOnlySpan<byte> ciphertext = wire60.Slice(AeadNonceBytes, PlaintextBytes);
        ReadOnlySpan<byte> tag = wire60.Slice(AeadNonceBytes + PlaintextBytes, TagBytes);

        using var aead = new ChaCha20Poly1305(key32);
        aead.Decrypt(nonce, ciphertext, tag, plaintext32, associatedData: ReadOnlySpan<byte>.Empty);
    }

    public static void EncodeMaster(
        ReadOnlySpan<byte> masterKey32,
        uint agentPid,
        ReadOnlySpan<byte> ivRandom8,
        uint ivCounter,
        ReadOnlySpan<byte> plaintext32,
        Span<byte> destination64,
        Span<byte> derivedAgentKey32)
    {
        if (masterKey32.Length != KeyBytes) throw new ArgumentException("masterKey must be 32 bytes", nameof(masterKey32));
        if (ivRandom8.Length != IvRandomBytes) throw new ArgumentException("ivRandom must be 8 bytes", nameof(ivRandom8));
        if (plaintext32.Length != PlaintextBytes) throw new ArgumentException("plaintext must be 32 bytes", nameof(plaintext32));
        if (destination64.Length != MasterFrameBytes) throw new ArgumentException($"destination must be {MasterFrameBytes} bytes", nameof(destination64));
        if (derivedAgentKey32.Length != KeyBytes) throw new ArgumentException("derivedAgentKey must be 32 bytes", nameof(derivedAgentKey32));

        Hkdf.DeriveAgentKey(masterKey32, agentPid, derivedAgentKey32);

        BinaryPrimitives.WriteUInt32LittleEndian(destination64[..AgentPidBytes], agentPid);
        ivRandom8.CopyTo(destination64.Slice(AgentPidBytes, IvRandomBytes));
        BinaryPrimitives.WriteUInt32LittleEndian(destination64.Slice(AgentPidBytes + IvRandomBytes, IvCounterBytes), ivCounter);

        Span<byte> nonce = stackalloc byte[AeadNonceBytes];
        ivRandom8.CopyTo(nonce);
        BinaryPrimitives.WriteUInt32LittleEndian(nonce[IvRandomBytes..], ivCounter);

        Span<byte> ciphertext = destination64.Slice(AgentPidBytes + AeadNonceBytes, PlaintextBytes);
        Span<byte> tag = destination64.Slice(AgentPidBytes + AeadNonceBytes + PlaintextBytes, TagBytes);
        ReadOnlySpan<byte> aad = destination64[..AgentPidBytes];

        using var aead = new ChaCha20Poly1305(derivedAgentKey32);
        aead.Encrypt(nonce, plaintext32, ciphertext, tag, associatedData: aad);
    }

    public static void DecodeMaster(ReadOnlySpan<byte> masterKey32, ReadOnlySpan<byte> wire64, Span<byte> plaintext32)
    {
        if (masterKey32.Length != KeyBytes) throw new ArgumentException("masterKey must be 32 bytes", nameof(masterKey32));
        if (wire64.Length != MasterFrameBytes) throw new ArgumentException($"wire must be {MasterFrameBytes} bytes", nameof(wire64));
        if (plaintext32.Length != PlaintextBytes) throw new ArgumentException($"plaintext must be {PlaintextBytes} bytes", nameof(plaintext32));

        uint agentPid = BinaryPrimitives.ReadUInt32LittleEndian(wire64[..AgentPidBytes]);
        Span<byte> agentKey = stackalloc byte[KeyBytes];
        Hkdf.DeriveAgentKey(masterKey32, agentPid, agentKey);

        ReadOnlySpan<byte> nonce = wire64.Slice(AgentPidBytes, AeadNonceBytes);
        ReadOnlySpan<byte> ciphertext = wire64.Slice(AgentPidBytes + AeadNonceBytes, PlaintextBytes);
        ReadOnlySpan<byte> tag = wire64.Slice(AgentPidBytes + AeadNonceBytes + PlaintextBytes, TagBytes);
        ReadOnlySpan<byte> aad = wire64[..AgentPidBytes];

        using var aead = new ChaCha20Poly1305(agentKey);
        aead.Decrypt(nonce, ciphertext, tag, plaintext32, associatedData: aad);
    }
}
