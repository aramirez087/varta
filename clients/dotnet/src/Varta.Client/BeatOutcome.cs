namespace Varta;

/// <summary>
/// Coarse-grained classification of a dropped beat. Matches the Rust
/// and Go client taxonomy.
/// </summary>
public enum DropReason
{
    KernelQueueFull = 1,
    NoObserver = 2,
    PeerGone = 3,
    StorageFull = 4,
}

/// <summary>
/// Detail accompanying an <see cref="BeatOutcome.IsFailed"/> outcome —
/// the underlying errno and its symbolic name.
/// </summary>
public readonly record struct BeatError(int Errno, string Kind)
{
    public override string ToString() => $"varta: beat failed (errno={Errno} kind={Kind})";
}

/// <summary>
/// Tagged result of <see cref="Varta.Beat"/>. Exactly one of
/// <see cref="IsSent"/>, <see cref="IsDropped"/>, <see cref="IsFailed"/>
/// is true.
/// </summary>
public readonly struct BeatOutcome
{
    private enum Tag : byte { Sent = 1, Dropped = 2, Failed = 3 }

    private readonly Tag _tag;
    private readonly DropReason _reason;
    private readonly BeatError _error;

    private BeatOutcome(Tag tag, DropReason reason, BeatError error)
    {
        _tag = tag;
        _reason = reason;
        _error = error;
    }

    public bool IsSent => _tag == Tag.Sent;
    public bool IsDropped => _tag == Tag.Dropped;
    public bool IsFailed => _tag == Tag.Failed;

    /// <summary>Valid only when <see cref="IsDropped"/> is true.</summary>
    public DropReason Reason => _reason;

    /// <summary>Valid only when <see cref="IsFailed"/> is true.</summary>
    public BeatError Error => _error;

    public static BeatOutcome Sent() => new(Tag.Sent, default, default);
    public static BeatOutcome Dropped(DropReason reason) => new(Tag.Dropped, reason, default);
    public static BeatOutcome Failed(BeatError error) => new(Tag.Failed, default, error);

    public override string ToString() => _tag switch
    {
        Tag.Sent => "Sent",
        Tag.Dropped => $"Dropped({_reason})",
        Tag.Failed => $"Failed({_error})",
        _ => "<invalid>",
    };
}
