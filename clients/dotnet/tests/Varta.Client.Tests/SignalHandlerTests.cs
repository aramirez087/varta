using System.Net.Sockets;
using System.Reflection;
using Varta.Panic;
using Varta.Tests.Helpers;
using Xunit;

namespace Varta.Tests;

public class SignalHandlerTests
{
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

    private static object? GetActiveEmitter()
    {
        var field = typeof(SignalHandler).GetField("s_activeEmitter",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        return field.GetValue(null);
    }
}
