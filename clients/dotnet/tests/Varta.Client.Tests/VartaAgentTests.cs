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
