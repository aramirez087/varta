using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using Varta.Internal.VlpSecure;
using Varta.Panic;
using Varta.Tests.Helpers;
using Xunit;

namespace Varta.Tests;

public class SignalHandlerTests
{
    [Fact]
    public void TerminalTimestampClaim_IsStrictAcrossClockResetAndCollision()
    {
        long highWater = 0;
        Assert.True(SignalHandler.TryClaimTerminalTimestamp(ref highWater, 100, out ulong first));
        Assert.Equal(100ul, first);
        Assert.True(SignalHandler.TryClaimTerminalTimestamp(ref highWater, 5, out ulong reset));
        Assert.Equal(101ul, reset);
        Assert.True(SignalHandler.TryClaimTerminalTimestamp(ref highWater, 101, out ulong equal));
        Assert.Equal(102ul, equal);

        highWater = long.MaxValue;
        Assert.False(SignalHandler.TryClaimTerminalTimestamp(ref highWater, 1, out _));
    }

    [SkipOnWindowsFact]
    public void InstallUds_BindsSocket_AndEmitFiresCriticalTerminalFrame()
    {
        string path = TmpUds.AllocatePath();
        using var recv = TmpUds.BindListener(path);

        using var reg = SignalHandler.InstallUds(path);

        // We invoke the emitter directly instead of raising a real signal
        // — keeps the test OS-agnostic and avoids racing with the
        // shutdown sequence. The Emit() method is the same code path the
        // PosixSignalRegistration callback invokes.
        var emitter = GetActiveEmitter();
        Assert.NotNull(emitter);
        var emitMethod = emitter!.GetType().GetMethod("Emit", BindingFlags.Instance | BindingFlags.Public)!;
        emitMethod.Invoke(emitter, null);

        byte[] buf = new byte[Frame.Bytes];
        Assert.True(TmpUds.TryReceive(recv, buf, out int n));
        Assert.Equal(Frame.Bytes, n);

        var frame = Frame.Decode(buf);
        Assert.Equal(Status.Critical, frame.Status);
        Assert.Equal(Frame.NonceTerminal, frame.Nonce);
        Assert.InRange(frame.Timestamp, 1ul, ulong.MaxValue - 1);

        File.Delete(path);
    }

    [Fact]
    public void InstallUds_OnMissingSocket_ThrowsSocketBind()
    {
        string path = "/tmp/varta-this-path-does-not-exist-" + Guid.NewGuid().ToString("N");
        var ex = Assert.Throws<PanicInstallException>(() => SignalHandler.InstallUds(path));
        Assert.Equal(PanicInstallErrorKind.SocketBind, ex.Kind);
    }

    [Fact]
    public void Run_OnException_EmitsAndRethrows()
    {
        // No emitter installed — Run must still re-throw the original exception.
        Assert.Throws<InvalidOperationException>(() =>
            SignalHandler.Run(() => throw new InvalidOperationException("boom")));
    }

    /// Fork-safety: a fork(2) child (PID != install PID) must re-read OS
    /// entropy for its IV rather than reuse the parent's. Without it, parent
    /// and child both seal a Critical frame under (key, iv, counter=0) — one
    /// ChaCha20-Poly1305 nonce — which is keystream + tag reuse.
    [Fact]
    public void SecureEmitter_OnFork_ReReadsEntropyInsteadOfReusingParentIv()
    {
        using var recv = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        recv.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        recv.ReceiveTimeout = 2000;
        int port = ((IPEndPoint)recv.LocalEndPoint!).Port;

        using var send = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        send.Connect(new IPEndPoint(IPAddress.Loopback, port));

        byte[] key = new byte[32];      // valid 32-byte ChaCha key
        byte[] installIv = new byte[8]; // known all-zero install IV

        // Spoof a fork: current PID differs from the install PID.
        var emitter = new SignalHandler.SecureEmitter(
            send, key, (byte[])installIv.Clone(), Environment.ProcessId + 1);
        emitter.Emit();

        byte[] buf = new byte[AeadCodec.SharedFrameBytes];
        int n = recv.Receive(buf);
        Assert.Equal(AeadCodec.SharedFrameBytes, n);

        // wire[0:8] is the iv_random prefix. The fork-recovery branch must have
        // replaced the all-zero install IV with fresh entropy.
        Assert.False(buf.Take(8).All(b => b == 0),
            "fork child must re-read entropy, not reuse the parent IV (nonce reuse)");
    }

    /// Control: when the PID matches the install PID (no fork), the install-time
    /// IV is used verbatim — the fork branch does not fire.
    [Fact]
    public void SecureEmitter_SamePid_UsesInstallIv()
    {
        using var recv = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        recv.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        recv.ReceiveTimeout = 2000;
        int port = ((IPEndPoint)recv.LocalEndPoint!).Port;

        using var send = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        send.Connect(new IPEndPoint(IPAddress.Loopback, port));

        byte[] key = new byte[32];
        byte[] installIv = { 1, 2, 3, 4, 5, 6, 7, 8 };

        var emitter = new SignalHandler.SecureEmitter(
            send, key, (byte[])installIv.Clone(), Environment.ProcessId);
        emitter.Emit();

        byte[] buf = new byte[AeadCodec.SharedFrameBytes];
        int n = recv.Receive(buf);
        Assert.Equal(AeadCodec.SharedFrameBytes, n);
        Assert.Equal(installIv, buf.Take(8).ToArray());
    }

    private static object? GetActiveEmitter()
    {
        var field = typeof(SignalHandler).GetField("s_activeEmitter",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        return field.GetValue(null);
    }
}
