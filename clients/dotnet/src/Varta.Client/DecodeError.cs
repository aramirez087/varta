namespace Varta;

/// <summary>
/// Discriminator for <see cref="DecodeError"/> failures returned by
/// <see cref="Frame.Decode"/>.
/// </summary>
public enum DecodeErrorKind
{
    BadMagic,
    BadVersion,
    BadCrc,
    BadStatus,
    StallOnWire,
    BadPid,
    BadTimestamp,
    BadNonce,
}

/// <summary>
/// Thrown by <see cref="Frame.Decode"/> when a wire buffer fails any of
/// the VLP v0.2 structural checks. Validation precedence follows the
/// spec: magic → version → CRC → status → StallOnWire → pid →
/// timestamp → nonce.
/// </summary>
public sealed class DecodeError : Exception
{
    public DecodeErrorKind Kind { get; }
    public string Detail { get; }

    public DecodeError(DecodeErrorKind kind, string detail)
        : base($"varta: decode failed: {kind} ({detail})")
    {
        Kind = kind;
        Detail = detail;
    }
}
