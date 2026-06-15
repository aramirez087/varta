using System.Net.Sockets;
using System.Runtime.InteropServices;
using Varta.Internal.Transport;
using Varta.Tests.Helpers;
using Xunit;

namespace Varta.Tests;

public class VartaAgentTests
{
    private static bool UnixOnly => !RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    /// <summary>
    /// Always drops on send; reconnect always throws. Drives the
    /// auto-reconnect threshold logic deterministically without sockets.
    /// </summary>
    private sealed class DropAndFailReconnect : IBeatTransport
    {
        public int Reconnects;

        public int Send(ReadOnlySpan<byte> frame32) =>
            throw new SocketException((int)SocketError.WouldBlock);

        public void Reconnect()
        {
            Reconnects++;
            throw new SocketException((int)SocketError.ConnectionRefused);
        }

        public void Dispose() { }
    }

    private sealed class CountingTransport : IBeatTransport
    {
        public int Sends;
        public int Reconnects;

        public int Send(ReadOnlySpan<byte> frame32)
        {
            Sends++;
            return frame32.Length;
        }

        public void Reconnect()
        {
            Reconnects++;
        }

        public void Dispose() { }
    }

    [Fact]
    public void Beat_RejectsObserverOnlyStallWithoutSideEffects()
    {
        var transport = new CountingTransport();
        using var agent = global::Varta.Varta.FromTransportForTest(transport);

        var outcome = agent.Beat((Status)0x03);

        Assert.True(outcome.IsFailed);
        Assert.Equal(0, outcome.Error.Errno);
        Assert.Equal("InvalidInput", outcome.Error.Kind);
        Assert.Equal(0, transport.Sends);
        Assert.Equal(0, transport.Reconnects);
    }

    [Fact]
    public void FailedReconnect_PreservesConsecutiveDropped_ForImmediateRetry()
    {
        // A failed auto-reconnect must NOT disarm the counter: once the
        // threshold is crossed, every subsequent Dropped beat retries the
        // reconnect immediately rather than re-arming a full window. Mirrors
        // the Rust regression and the frozen cross-client contract (reset
        // only on a successful reconnect).
        var transport = new DropAndFailReconnect();
        using var agent = global::Varta.Varta.FromTransportForTest(transport);
        agent.SetReconnectAfter(2);

        // First drop: 0 -> 1, below threshold, no reconnect attempted.
        Assert.True(agent.Beat(Status.Ok).IsDropped);
        Assert.Equal(0, transport.Reconnects);

        // Second drop: crosses the threshold; reconnect attempted and
        // FAILS, so the counter must stay saturated at 2.
        Assert.True(agent.Beat(Status.Ok).IsDropped);
        Assert.Equal(1, transport.Reconnects);

        // Third drop: threshold still crossed → reconnect retried immediately.
        Assert.True(agent.Beat(Status.Ok).IsDropped);
        Assert.Equal(2, transport.Reconnects);
    }

    [SkipOnWindowsFact]
    public void Beat_OnUds_SendsValidFrame()
    {
        string path = TmpUds.AllocatePath();
        using var recv = TmpUds.BindListener(path);

        using var agent = global::Varta.Varta.Connect(path);
        var outcome = agent.Beat(Status.Ok, payload: 42);
        Assert.True(outcome.IsSent, $"expected Sent, got {outcome}");

        byte[] buf = new byte[Frame.Bytes];
        Assert.True(TmpUds.TryReceive(recv, buf, out int n));
        Assert.Equal(Frame.Bytes, n);

        var frame = Frame.Decode(buf);
        Assert.Equal(Status.Ok, frame.Status);
        Assert.Equal((uint)Environment.ProcessId, frame.Pid);
        Assert.Equal(42u, frame.Payload);
        Assert.Equal(1ul, frame.Nonce); // first beat

        File.Delete(path);
    }

    [SkipOnWindowsFact]
    public void Beat_AfterObserverGone_ReturnsDropped()
    {
        string path = TmpUds.AllocatePath();
        var recv = TmpUds.BindListener(path);

        using var agent = global::Varta.Varta.Connect(path);
        Assert.True(agent.Beat(Status.Ok).IsSent);

        // Observer disappears.
        recv.Dispose();
        File.Delete(path);

        // Subsequent beats should classify as Dropped (NoObserver) on Linux/macOS.
        var outcome = agent.Beat(Status.Ok);
        Assert.True(outcome.IsSent || outcome.IsDropped,
            $"expected Sent or Dropped, got {outcome}");
        // We don't strictly assert Dropped because some kernels accept the
        // datagram and only later signal the loss (UDS is connection-less).
    }

    [SkipOnWindowsFact]
    public void ForkRecovery_IncrementsCounterAndRebuildsTransport()
    {
        string path = TmpUds.AllocatePath();
        using var recv = TmpUds.BindListener(path);

        using var agent = global::Varta.Varta.Connect(path);
        Assert.Equal(0ul, agent.ForkRecoveries);

        // Simulate fork by injecting a different "connect PID".
        agent.SetConnectPidForTest(Environment.ProcessId + 1);

        var outcome = agent.Beat(Status.Ok);
        Assert.True(outcome.IsSent);
        Assert.Equal(1ul, agent.ForkRecoveries);

        // Nonce should reset to start of a new sequence (1 → +1 after this beat).
        Assert.Equal(2ul, agent.NonceForTest);
    }

    // -----------------------------------------------------------------------
    // Commit-on-success: a Dropped or Failed send must NOT advance the
    // committed nonce/timestamp. NonceForTest exposes the *next* nonce, so it
    // stays at its current value until a frame is actually accepted. Mirrors
    // the Rust regressions in crates/varta-client/src/client.rs::tests and the
    // Python / Go / Node equivalents.
    // -----------------------------------------------------------------------

    /// <summary>Drops every send; reconnect succeeds (no-op).</summary>
    private sealed class AlwaysDrop : IBeatTransport
    {
        public int Send(ReadOnlySpan<byte> frame32) =>
            throw new SocketException((int)SocketError.WouldBlock);

        public void Reconnect() { }

        public void Dispose() { }
    }

    /// <summary>Fails every send with a non-droppable error → BeatOutcome.Failed.</summary>
    private sealed class AlwaysFail : IBeatTransport
    {
        public int Send(ReadOnlySpan<byte> frame32) =>
            throw new SocketException((int)SocketError.AccessDenied);

        public void Reconnect() { }

        public void Dispose() { }
    }

    /// <summary>Drops the first N sends, then accepts; reconnect succeeds.</summary>
    private sealed class DropThenSend : IBeatTransport
    {
        private int _remaining;
        public int Sends;

        public DropThenSend(int drops) => _remaining = drops;

        public int Send(ReadOnlySpan<byte> frame32)
        {
            Sends++;
            if (_remaining > 0)
            {
                _remaining--;
                throw new SocketException((int)SocketError.WouldBlock);
            }
            return frame32.Length;
        }

        public void Reconnect() { }

        public void Dispose() { }
    }

    [Fact]
    public void DroppedBeat_DoesNotCommitNonce()
    {
        using var agent = global::Varta.Varta.FromTransportForTest(new AlwaysDrop());
        Assert.Equal(1ul, agent.NonceForTest);
        Assert.True(agent.Beat(Status.Ok).IsDropped);
        // Candidate nonce 1 was built and sent but rejected → not committed.
        Assert.Equal(1ul, agent.NonceForTest);
        Assert.True(agent.Beat(Status.Ok).IsDropped);
        Assert.Equal(1ul, agent.NonceForTest);
    }

    [Fact]
    public void FailedBeat_DoesNotCommitNonce()
    {
        using var agent = global::Varta.Varta.FromTransportForTest(new AlwaysFail());
        Assert.True(agent.Beat(Status.Ok).IsFailed);
        Assert.Equal(1ul, agent.NonceForTest);
    }

    [Fact]
    public void FirstAcceptedBeatAfterDrop_ReusesNonceOne()
    {
        using var agent = global::Varta.Varta.FromTransportForTest(new DropThenSend(1));
        Assert.True(agent.Beat(Status.Ok).IsDropped);
        Assert.Equal(1ul, agent.NonceForTest); // not burned by the drop
        Assert.True(agent.Beat(Status.Ok).IsSent);
        // The accepted frame carried nonce 1; the next nonce is now 2.
        Assert.Equal(2ul, agent.NonceForTest);
    }

    [Fact]
    public void SaturatingNanosFromTicks_SaturatesInsteadOfOverflowingIntoSentinel()
    {
        // Regression (bug-474): the wire timestamp is `ticks * 100` (100-ns
        // Stopwatch ticks -> ns) in signed-long arithmetic. After a multi-century
        // single-handle uptime that overflows `long` negative, and the (ulong)
        // cast lands near the reserved u64::MAX BadTimestamp sentinel (which the
        // observer drops). The converter must saturate instead — matching the
        // panic path (SignalHandler.BuildCriticalFrame) and the Rust client.
        Assert.Equal(100_000UL, global::Varta.Varta.SaturatingNanosFromTicks(1000));
        // At/over the overflow threshold it saturates to long.MaxValue ns, NOT a
        // wrapped value near u64::MAX (without the guard this returns
        // 18446744073709551516, failing this assertion).
        Assert.Equal(
            (ulong)long.MaxValue,
            global::Varta.Varta.SaturatingNanosFromTicks(long.MaxValue));
        Assert.Equal(
            (ulong)long.MaxValue,
            global::Varta.Varta.SaturatingNanosFromTicks(long.MaxValue / 100 + 1));
        // Saturated value is below the BadTimestamp sentinel, so a saturated
        // agent's beats are never rejected as the reserved u64::MAX.
        Assert.True(global::Varta.Varta.SaturatingNanosFromTicks(long.MaxValue) < ulong.MaxValue);
    }

    [Fact]
    public void ReconnectRetry_CommitsNonceOnlyOnSuccessfulRetry()
    {
        var transport = new DropThenSend(2);
        using var agent = global::Varta.Varta.FromTransportForTest(transport);
        agent.SetReconnectAfter(2);
        Assert.True(agent.Beat(Status.Ok).IsDropped);
        Assert.Equal(1ul, agent.NonceForTest);
        // Second drop crosses the threshold; reconnect succeeds, retry sends.
        Assert.True(agent.Beat(Status.Ok).IsSent);
        Assert.Equal(2ul, agent.NonceForTest);
        Assert.Equal(3, transport.Sends); // 2 drops + 1 retry
    }

    [Fact]
    public void Connect_OnWindows_ThrowsPlatformNotSupported()
    {
        if (UnixOnly) return; // not Windows — silently skip via early return
        Assert.Throws<PlatformNotSupportedException>(() =>
            global::Varta.Varta.Connect("\\\\.\\pipe\\varta"));
    }
}

/// <summary>
/// xUnit Fact that is silently skipped (test reported as Skipped, not
/// Failed) when the runtime is Windows. Keeps the test count consistent
/// across platforms without requiring an extra NuGet skip package.
/// </summary>
internal sealed class SkipOnWindowsFactAttribute : FactAttribute
{
    public SkipOnWindowsFactAttribute()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Skip = "UDS (AF_UNIX SOCK_DGRAM) is not supported on Windows.";
        }
    }
}
