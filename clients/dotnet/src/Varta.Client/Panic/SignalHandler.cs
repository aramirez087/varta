using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Varta.Internal.Vlp;
using Varta.Internal.VlpSecure;

namespace Varta.Panic;

/// <summary>
/// Discriminator for <see cref="PanicInstallException"/> failures.
/// </summary>
public enum PanicInstallErrorKind
{
    /// <summary>Socket bind / connect failed at install time.</summary>
    SocketBind,
    /// <summary>Key material had the wrong length / format.</summary>
    BadKey,
    /// <summary>The OS RNG refused to provide entropy (rare; fail-closed).</summary>
    EntropyUnavailable,
}

/// <summary>
/// Thrown by <see cref="SignalHandler.InstallUds(string)"/> et al. when
/// the installer cannot pre-bind the emit socket. Loud failure is the
/// design — a silently-broken hook is the failure mode operators cannot
/// diagnose.
/// </summary>
public sealed class PanicInstallException : Exception
{
    public PanicInstallErrorKind Kind { get; }

    public PanicInstallException(PanicInstallErrorKind kind, string message, Exception? inner = null)
        : base(message, inner)
    {
        Kind = kind;
    }
}

/// <summary>
/// Best-effort emitter that fires a terminal Critical beat
/// (<see cref="Frame.NonceTerminal"/>) before the process exits.
/// Mirrors the Rust <c>install_panic_handler*</c> family and the Go
/// <c>panic.InstallSignalHandler*</c> APIs.
/// </summary>
/// <remarks>
/// <para>
/// Two emit paths:
/// </para>
/// <list type="number">
///   <item>
///     <see cref="InstallUds"/> / <see cref="InstallUdp"/> /
///     <see cref="InstallSecureUdp"/> register
///     <see cref="PosixSignalRegistration"/> handlers for
///     SIGTERM / SIGINT / SIGQUIT / SIGHUP. The .NET runtime invokes
///     the callback on a dedicated managed thread (NOT the real
///     signal-handler context), so <see cref="Socket.Send(ReadOnlySpan{byte}, SocketFlags)"/>
///     is safe.
///   </item>
///   <item>
///     <see cref="Run"/> wraps a delegate in try/catch — any escaped
///     <see cref="Exception"/> triggers an emit and then re-throws so
///     the normal stack trace still prints. This is the .NET analogue
///     of Rust's <c>std::panic::set_hook</c>.
///   </item>
/// </list>
/// <para>
/// .NET 10 caveat: the runtime no longer auto-graceful-shuts on
/// SIGTERM. This handler intentionally does not call
/// <c>Environment.Exit</c> — it only emits the beat. Host shutdown
/// remains the application's responsibility.
/// </para>
/// </remarks>
public static class SignalHandler
{
    private static Emitter? s_activeEmitter;

    /// <summary>
    /// Install a UDS-backed signal emitter. The socket is bound at
    /// install time so the signal-driven path performs only the in-kernel
    /// <c>send(2)</c>.
    /// </summary>
    public static IDisposable InstallUds(string socketPath)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException(
                "UDS signal handlers are not supported on Windows; use InstallUdp instead.");
        }
        Socket sock;
        try
        {
            sock = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
            sock.Connect(new UnixDomainSocketEndPoint(socketPath));
            sock.Blocking = false;
        }
        catch (Exception ex)
        {
            throw new PanicInstallException(PanicInstallErrorKind.SocketBind,
                $"failed to bind UDS at {socketPath}: {ex.Message}", ex);
        }
        return InstallPlaintext(new PlaintextEmitter(sock));
    }

    /// <summary>Install a plaintext-UDP signal emitter.</summary>
    public static IDisposable InstallUdp(string host, int port)
    {
        ArgumentNullException.ThrowIfNull(host);
        Socket sock;
        try
        {
            sock = BuildUdp(host, port);
        }
        catch (Exception ex)
        {
            throw new PanicInstallException(PanicInstallErrorKind.SocketBind,
                $"failed to bind UDP to {host}:{port}: {ex.Message}", ex);
        }
        return InstallPlaintext(new PlaintextEmitter(sock));
    }

    /// <summary>
    /// Install a ChaCha20-Poly1305 secure-UDP signal emitter. Reads the
    /// 8-byte IV from <see cref="RandomNumberGenerator.Fill"/> at
    /// install time and fails closed
    /// (<see cref="PanicInstallErrorKind.EntropyUnavailable"/>) if the
    /// RNG throws. The emitter snapshots the install-time PID and
    /// re-reads entropy on a detected fork(2).
    /// </summary>
    public static IDisposable InstallSecureUdp(string host, int port, ReadOnlySpan<byte> key32)
    {
        ArgumentNullException.ThrowIfNull(host);
        if (key32.Length != Hkdf.KeyBytes)
        {
            throw new PanicInstallException(PanicInstallErrorKind.BadKey,
                $"key must be {Hkdf.KeyBytes} bytes; got {key32.Length}");
        }
        if (!ChaCha20Poly1305.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "ChaCha20-Poly1305 is not available on this platform / .NET runtime.");
        }
        byte[] iv = new byte[AeadCodec.IvRandomBytes];
        try
        {
            RandomNumberGenerator.Fill(iv);
        }
        catch (Exception ex)
        {
            throw new PanicInstallException(PanicInstallErrorKind.EntropyUnavailable,
                $"OS RNG failed: {ex.Message}", ex);
        }
        Socket sock;
        try
        {
            sock = BuildUdp(host, port);
        }
        catch (Exception ex)
        {
            throw new PanicInstallException(PanicInstallErrorKind.SocketBind,
                $"failed to bind UDP to {host}:{port}: {ex.Message}", ex);
        }
        var emitter = new SecureEmitter(sock, key32.ToArray(), iv);
        return InstallEmitter(emitter);
    }

    /// <summary>
    /// Run <paramref name="action"/> with panic-style protection. If
    /// <paramref name="action"/> throws, the most-recently-installed
    /// emitter fires a terminal Critical beat before the exception is
    /// re-thrown. If no emitter is installed, this is a plain delegate
    /// invocation.
    /// </summary>
    public static void Run(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        try
        {
            action();
        }
        catch
        {
            Volatile.Read(ref s_activeEmitter)?.Emit();
            throw;
        }
    }

    // ---- Internal plumbing ----

    private static CompositeDisposable InstallPlaintext(PlaintextEmitter emitter) => InstallEmitter(emitter);

    private static CompositeDisposable InstallEmitter(Emitter emitter)
    {
        Volatile.Write(ref s_activeEmitter, emitter);
        var regs = new[]
        {
            PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => emitter.Emit()),
            PosixSignalRegistration.Create(PosixSignal.SIGINT,  _ => emitter.Emit()),
            PosixSignalRegistration.Create(PosixSignal.SIGQUIT, _ => emitter.Emit()),
            PosixSignalRegistration.Create(PosixSignal.SIGHUP,  _ => emitter.Emit()),
        };
        return new CompositeDisposable(regs, emitter);
    }

    private static Socket BuildUdp(string host, int port)
    {
        var addresses = Dns.GetHostAddresses(host);
        if (addresses.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
        var addr = addresses[0];
        var family = addr.AddressFamily == AddressFamily.InterNetworkV6
            ? AddressFamily.InterNetworkV6
            : AddressFamily.InterNetwork;
        var s = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            s.Connect(new IPEndPoint(addr, port));
            s.Blocking = false;
            return s;
        }
        catch
        {
            s.Dispose();
            throw;
        }
    }

    // ---- Emitter types ----

    internal abstract class Emitter : IDisposable
    {
        protected readonly Socket Socket;
        private int _fired; // 0 = not yet fired; 1 = fired

        protected Emitter(Socket socket) => Socket = socket;

        public void Emit()
        {
            // One-shot — the same handler may fire from multiple signals
            // and from Run(); only the first invocation does work.
            if (Interlocked.Exchange(ref _fired, 1) != 0) return;
            try
            {
                Span<byte> buf = stackalloc byte[Frame.Bytes];
                BuildCriticalFrame(buf);
                EmitFrame(buf);
            }
            catch
            {
                // Best-effort — never let an emit attempt itself throw.
            }
        }

        protected abstract void EmitFrame(ReadOnlySpan<byte> plaintext32);

        private static void BuildCriticalFrame(Span<byte> dest)
        {
            uint pid = (uint)Environment.ProcessId;
            // Timestamp must not equal u64::MAX; use any safe value.
            ulong ts = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() * 1_000_000ul;
            if (ts == ulong.MaxValue) ts = ulong.MaxValue - 1;
            Codec.EncodeInto(dest, Status.Critical, pid, ts, Frame.NonceTerminal, payload: 0);
        }

        public void Dispose()
        {
            try { Socket.Dispose(); } catch { /* best-effort */ }
        }
    }

    internal sealed class PlaintextEmitter : Emitter
    {
        public PlaintextEmitter(Socket socket) : base(socket) { }
        protected override void EmitFrame(ReadOnlySpan<byte> plaintext32)
        {
            Socket.Send(plaintext32, SocketFlags.None);
        }
    }

    internal sealed class SecureEmitter : Emitter
    {
        private readonly byte[] _key;
        private byte[] _iv;
        private readonly int _installPid;

        public SecureEmitter(Socket socket, byte[] key32, byte[] iv8) : base(socket)
        {
            _key = key32;
            _iv = iv8;
            _installPid = Environment.ProcessId;
        }

        // Test seam: spoof the install-time PID so the fork-recovery branch in
        // EmitFrame can be exercised without an actual fork(2).
        internal SecureEmitter(Socket socket, byte[] key32, byte[] iv8, int installPidForTest)
            : base(socket)
        {
            _key = key32;
            _iv = iv8;
            _installPid = installPidForTest;
        }

        protected override void EmitFrame(ReadOnlySpan<byte> plaintext32)
        {
            // Fork-safety (mirrors the Rust/Go secure panic emitters and this
            // type's documented contract). Emit() is one-shot per process, so
            // counter 0 is the only counter ever used in a given process — a
            // unique IV per process is therefore sufficient. But a fork(2)
            // child inherits the parent's IV and its own fresh `_fired` flag,
            // so parent and child could each seal a Critical frame under the
            // same (key, iv, counter=0) ChaCha20-Poly1305 nonce — catastrophic
            // keystream + Poly1305 reuse. Detect the fork by PID change and
            // re-read OS entropy so the child's nonce space is disjoint. Fail
            // closed if the RNG is unavailable rather than reuse the parent's.
            if (Environment.ProcessId != _installPid)
            {
                byte[] freshIv = new byte[AeadCodec.IvRandomBytes];
                try
                {
                    RandomNumberGenerator.Fill(freshIv);
                }
                catch
                {
                    return;
                }
                _iv = freshIv;
            }
            Span<byte> wire = stackalloc byte[AeadCodec.SharedFrameBytes];
            AeadCodec.EncodeShared(_key, _iv, ivCounter: 0, plaintext32, wire);
            Socket.Send(wire, SocketFlags.None);
        }
    }

    internal sealed class CompositeDisposable : IDisposable
    {
        private readonly IDisposable[] _items;
        private readonly Emitter _emitter;
        public CompositeDisposable(IDisposable[] items, Emitter emitter)
        {
            _items = items;
            _emitter = emitter;
        }
        public void Dispose()
        {
            foreach (var it in _items) { try { it.Dispose(); } catch { /* best-effort */ } }
            try { _emitter.Dispose(); } catch { /* best-effort */ }
            // Drop our reference if we were the active emitter.
            Interlocked.CompareExchange(ref s_activeEmitter, null, _emitter);
        }
    }
}
