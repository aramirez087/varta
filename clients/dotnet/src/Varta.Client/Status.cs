namespace Varta;

/// <summary>
/// Health status carried in a Varta beat frame. The byte value is the
/// VLP v0.2 wire encoding (see <c>book/src/spec/vlp.md</c>).
/// </summary>
/// <remarks>
/// <see cref="Status"/> deliberately omits <c>Stall</c> (0x03) — that
/// variant is observer-synthesised and is rejected on the wire by
/// <see cref="Frame.Decode"/> as <see cref="DecodeErrorKind.StallOnWire"/>.
/// </remarks>
public enum Status : byte
{
    /// <summary>Agent is healthy.</summary>
    Ok = 0x00,

    /// <summary>Agent is operational but degraded.</summary>
    Degraded = 0x01,

    /// <summary>Agent is in a critical state.</summary>
    Critical = 0x02,
}
