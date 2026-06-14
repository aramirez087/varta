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

    /// The secure panic emitter must DERIVE its 8-byte IV prefix from the
    /// install-time salt plus the per-fire (pid, timestamp) that are sealed in
    /// the authenticated plaintext — never a raw stored IV. Decrypting the wire
    /// recovers (pid, timestamp); re-deriving from (salt, pid, ts, counter=0)
    /// must reproduce the on-wire prefix exactly. This is the bug-446
    /// structural fix that brings .NET to parity with the Rust/Go/Python/Node
    /// clients: a fork(2) child (distinct pid) and a PID-recycled descendant
    /// (later monotonic timestamp) both get a disjoint nonce by construction,
    /// with no install-PID probe and no in-hook entropy read.
    [Fact]
    public void SecureEmitter_DerivesIvPrefixFromSaltAndAuthenticatedMeta()
    {
        using var recv = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        recv.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        recv.ReceiveTimeout = 2000;
        int port = ((IPEndPoint)recv.LocalEndPoint!).Port;

        using var send = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        send.Connect(new IPEndPoint(IPAddress.Loopback, port));

        byte[] key = new byte[32];
        byte[] salt = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();

        var emitter = new SignalHandler.SecureEmitter(send, key, (byte[])salt.Clone());
        emitter.Emit();

        byte[] wire = new byte[AeadCodec.SharedFrameBytes];
        int n = recv.Receive(wire);
        Assert.Equal(AeadCodec.SharedFrameBytes, n);

        // Decrypt with the shared key — succeeds only if the on-wire iv_random
        // prefix matches the nonce used to seal, recovering (pid, timestamp).
        byte[] plaintext = new byte[AeadCodec.PlaintextBytes];
        AeadCodec.DecodeShared(key, wire, plaintext);
        var frame = Frame.Decode(plaintext);
        Assert.Equal(Status.Critical, frame.Status);
        Assert.Equal(Frame.NonceTerminal, frame.Nonce);

        // The transmitted prefix MUST equal HKDF(salt, pid, timestamp, 0) —
        // proving it is derived from the authenticated meta, not a raw IV.
        byte[] expectedPrefix = new byte[AeadCodec.IvRandomBytes];
        Hkdf.DerivePanicIvPrefix(salt, frame.Pid, frame.Timestamp, 0, expectedPrefix);
        Assert.Equal(expectedPrefix, wire.Take(AeadCodec.IvRandomBytes).ToArray());
        Assert.NotEqual(salt.Take(8).ToArray(), wire.Take(8).ToArray());
    }

    private static object? GetActiveEmitter()
    {
        var field = typeof(SignalHandler).GetField("s_activeEmitter",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        return field.GetValue(null);
    }
}
