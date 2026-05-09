using System.Net.Sockets;

namespace Varta.Internal.Errno;

/// <summary>
/// Maps a <see cref="SocketException"/> raised by a hot-path
/// <c>send(2)</c> to a <see cref="BeatOutcome"/>. Mirrors the four-way
/// taxonomy used by the Rust / Go / Python / Node clients.
/// </summary>
/// <remarks>
/// The classification is intentionally conservative: any errno not
/// recognised by this table surfaces as <see cref="BeatOutcome.Failed(BeatError)"/>
/// rather than silently mapped to <see cref="BeatOutcome.Dropped(DropReason)"/>.
/// Unexpected failures should be visible to the application, not hidden
/// as routine backpressure.
/// </remarks>
internal static class ErrnoClassifier
{
    // Linux and macOS both use ENOENT = 2 and ENOSPC = 28. We read the
    // native errno via SocketException.NativeErrorCode (Unix-style on
    // those platforms; on Windows these constants are unused).
    private const int Enoent = 2;
    private const int Enospc = 28;

    public static BeatOutcome Classify(SocketException ex)
    {
        SocketError code = ex.SocketErrorCode;
        int errno = ex.NativeErrorCode;

        // KernelQueueFull — transient kernel saturation. The agent
        // produced beats faster than the observer drained them.
        if (code == SocketError.WouldBlock || code == SocketError.NoBufferSpaceAvailable)
        {
            // ENOSPC reported via NoBufferSpaceAvailable means the host
            // disk is full (typically surfaced by an audit-log write on
            // the observer side, but defensively classified here).
            if (errno == Enospc)
            {
                return BeatOutcome.Dropped(DropReason.StorageFull);
            }
            return BeatOutcome.Dropped(DropReason.KernelQueueFull);
        }

        // NoObserver — observer is not bound or the UDS path is gone.
        if (code == SocketError.ConnectionRefused || code == SocketError.AddressNotAvailable
            || code == SocketError.HostUnreachable || errno == Enoent)
        {
            return BeatOutcome.Dropped(DropReason.NoObserver);
        }

        // PeerGone — the live channel has disappeared mid-stream.
        if (code == SocketError.ConnectionReset || code == SocketError.NotConnected
            || code == SocketError.Shutdown || code == SocketError.Disconnecting)
        {
            return BeatOutcome.Dropped(DropReason.PeerGone);
        }

        // StorageFull — disk pressure on a UDS path.
        if (errno == Enospc)
        {
            return BeatOutcome.Dropped(DropReason.StorageFull);
        }

        // Anything else: surface as Failed with the underlying errno.
        return BeatOutcome.Failed(new BeatError(errno, code.ToString()));
    }
}
