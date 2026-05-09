using Varta.Internal.Vlp;

namespace Varta;

/// <summary>
/// A decoded VLP v0.2 base frame. Construct via <see cref="Decode"/>.
/// </summary>
public readonly struct Frame
{
    /// <summary>Wire size in bytes of a VLP v0.2 base frame.</summary>
    public const int Bytes = 32;

    /// <summary>
    /// Sentinel nonce signalling a terminal Critical beat (e.g. emitted
    /// by a panic / signal handler). Only legal on the wire paired with
    /// <see cref="Status.Critical"/>.
    /// </summary>
    public const ulong NonceTerminal = 0xFFFF_FFFF_FFFF_FFFFul;

    public Status Status { get; }
    public uint Pid { get; }
    public ulong Timestamp { get; }
    public ulong Nonce { get; }
    public uint Payload { get; }

    internal Frame(Status status, uint pid, ulong timestamp, ulong nonce, uint payload)
    {
        Status = status;
        Pid = pid;
        Timestamp = timestamp;
        Nonce = nonce;
        Payload = payload;
    }

    /// <summary>
    /// Parse a 32-byte VLP v0.2 wire frame. Throws <see cref="DecodeError"/>
    /// on any structural violation.
    /// </summary>
    public static Frame Decode(ReadOnlySpan<byte> wire) => Codec.Decode(wire);
}
