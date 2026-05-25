using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;
using Varta.Internal.Errno;
using Varta.Internal.Transport;
using Varta.Internal.Vlp;
using Varta.Internal.VlpSecure;

namespace Varta;

/// <summary>
/// Varta agent — emits VLP v0.2 health beats to a local observer over a
/// configured transport. Construct via one of the <c>Connect*</c>
/// factories, then call <see cref="Beat"/> on whatever cadence the
/// application chooses (typically every 500 ms – 5 s).
/// </summary>
/// <remarks>
/// <para>
/// Thread-safe via a single internal mutex; concurrent <see cref="Beat"/>
/// callers serialise. The mutex is uncontended in the common case of one
/// thread per agent.
/// </para>
/// <para>
/// Fork-safety: <see cref="Beat"/> compares the live
/// <see cref="Environment.ProcessId"/> against the PID snapshot taken at
/// <see cref="Connect"/> time. On mismatch (i.e. running in a forked
/// child) the transport is rebuilt — for secure UDP that re-reads the
/// session salt from OS entropy. The recovery count is exposed via
/// <see cref="ForkRecoveries"/>.
/// </para>
/// </remarks>
[SuppressMessage("Naming", "CA1724:Type names should not match namespaces",
    Justification = "The class name 'Varta' is the agreed public surface — matches the package id Varta.Client and the namespace convention used by all peer clients (Rust crates/varta-client::Varta, Go varta.Varta, Python varta.Varta).")]
public sealed class Varta : IDisposable
{
    /// <summary>Wire size of a VLP v0.2 base frame.</summary>
    public const int FrameBytes = Frame.Bytes;

    /// <summary>
    /// Sentinel nonce signalling a terminal Critical beat. Only legal on
    /// the wire paired with <see cref="Status.Critical"/>.
    /// </summary>
    public const ulong NonceTerminal = Frame.NonceTerminal;

    private readonly IBeatTransport _transport;
    private readonly object _lock = new();
    private readonly byte[] _scratch = new byte[FrameBytes];
    private readonly long _startTimestamp = Stopwatch.GetTimestamp();

    private int _connectPid;
    private ulong _nonce = 1;
    private ulong _lastTimestamp;
    private ulong _clockRegressions;
    private ulong _forkRecoveries;
    private uint _consecutiveDropped;
    private uint _reconnectAfter;
    private bool _disposed;

    private Varta(IBeatTransport transport)
    {
        _transport = transport;
        _connectPid = Environment.ProcessId;
    }

    /// <summary>
    /// Connect to a Varta observer over a Unix Domain Socket
    /// (<c>AF_UNIX</c> + <c>SOCK_DGRAM</c>). Linux and macOS only —
    /// throws <see cref="PlatformNotSupportedException"/> on Windows
    /// (use <see cref="ConnectUdp"/> instead).
    /// </summary>
    public static Varta Connect(string socketPath)
    {
        ArgumentNullException.ThrowIfNull(socketPath);
        return new Varta(new UdsTransport(socketPath));
    }

    /// <summary>
    /// Connect via plaintext UDP. Dev / loopback use only — production
    /// deployments should prefer <see cref="Connect"/> (UDS,
    /// kernel-attested) or <see cref="ConnectSecureUdp"/>
    /// (AEAD-authenticated).
    /// </summary>
    public static Varta ConnectUdp(string host, int port)
    {
        ArgumentNullException.ThrowIfNull(host);
        return new Varta(new UdpTransport(host, port));
    }

    /// <summary>
    /// Connect via ChaCha20-Poly1305 AEAD UDP using a 32-byte pre-shared
    /// key. Produces 60-byte wire frames.
    /// </summary>
    public static Varta ConnectSecureUdp(string host, int port, ReadOnlySpan<byte> key32)
    {
        ArgumentNullException.ThrowIfNull(host);
        return new Varta(new SecureUdpTransport(SecureUdpMode.Shared, host, port, key32));
    }

    /// <summary>
    /// Connect via ChaCha20-Poly1305 AEAD UDP using a 32-byte master
    /// key; the per-agent key is HKDF-derived from the master key and
    /// the current PID. Produces 64-byte wire frames; agent_pid is bound
    /// as AAD.
    /// </summary>
    public static Varta ConnectSecureUdpWithMaster(string host, int port, ReadOnlySpan<byte> masterKey32)
    {
        ArgumentNullException.ThrowIfNull(host);
        return new Varta(new SecureUdpTransport(SecureUdpMode.Master, host, port, masterKey32));
    }

    /// <summary>
    /// Emit one beat. The call is non-blocking; a full kernel queue
    /// surfaces as <see cref="BeatOutcome.Dropped"/> with
    /// <see cref="DropReason.KernelQueueFull"/> — never an exception.
    /// </summary>
    public BeatOutcome Beat(Status status, uint payload = 0)
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            // Per-emission PID read — never cache.
            int currentPid = Environment.ProcessId;
            if (currentPid != _connectPid)
            {
                _transport.Reconnect();
                _connectPid = currentPid;
                _nonce = 1;
                _lastTimestamp = 0;
                _forkRecoveries = SaturatingIncrement(_forkRecoveries);
            }

            // Monotonic ns since this Varta was constructed. Stopwatch.GetElapsedTime
            // is unaffected by NTP adjustments. TimeSpan.Ticks = 100 ns.
            ulong nowNs = (ulong)(Stopwatch.GetElapsedTime(_startTimestamp).Ticks * 100L);
            if (nowNs < _lastTimestamp)
            {
                _clockRegressions = SaturatingIncrement(_clockRegressions);
                nowNs = _lastTimestamp;
            }
            _lastTimestamp = nowNs;

            ulong nonce = _nonce;
            if (_nonce < NonceTerminal - 1)
            {
                _nonce++;
            }
            else
            {
                _nonce = 0; // wraparound; observer treats this as a fresh sequence
            }

            Codec.EncodeInto(_scratch, status, (uint)currentPid, nowNs, nonce, payload);

            return TrySendWithReconnectAfter(allowRetry: true);
        }
    }

    private BeatOutcome TrySendWithReconnectAfter(bool allowRetry)
    {
        try
        {
            _transport.Send(_scratch);
            _consecutiveDropped = 0;
            return BeatOutcome.Sent();
        }
        catch (SocketException ex)
        {
            var outcome = ErrnoClassifier.Classify(ex);
            if (outcome.IsDropped)
            {
                _consecutiveDropped = SaturatingIncrementU32(_consecutiveDropped);
                if (allowRetry && _reconnectAfter > 0 && _consecutiveDropped >= _reconnectAfter)
                {
                    _consecutiveDropped = 0;
                    try
                    {
                        _transport.Reconnect();
                        _connectPid = Environment.ProcessId;
                        return TrySendWithReconnectAfter(allowRetry: false);
                    }
                    catch
                    {
                        // Reconnect failed — surface the original dropped outcome.
                    }
                }
            }
            return outcome;
        }
    }

    /// <summary>
    /// Force a transport rebuild and refresh the connect-time PID
    /// snapshot. For secure UDP, also re-reads the session salt from OS
    /// entropy. Useful after a known fork(2) or to recover from a
    /// half-open peer.
    /// </summary>
    public void Reconnect()
    {
        lock (_lock)
        {
            _transport.Reconnect();
            _connectPid = Environment.ProcessId;
            _consecutiveDropped = 0;
        }
    }

    /// <summary>
    /// Enable auto-reconnect after <paramref name="n"/> consecutive
    /// dropped beats. Set to 0 to disable. Counter resets on any Sent
    /// outcome.
    /// </summary>
    public void SetReconnectAfter(uint n)
    {
        lock (_lock)
        {
            _reconnectAfter = n;
        }
    }

    /// <summary>
    /// Saturating count of fork(2) auto-recoveries detected by
    /// <see cref="Beat"/>. Publish this as a Prometheus gauge under your
    /// chosen metric name (suggested: <c>varta_client_fork_recoveries_total</c>).
    /// </summary>
    public ulong ForkRecoveries
    {
        get { lock (_lock) { return _forkRecoveries; } }
    }

    /// <summary>
    /// Saturating count of detected platform-clock regressions
    /// (<see cref="Stopwatch"/> regressions are extraordinarily rare but
    /// possible on virtualised hosts). Publish as a Prometheus gauge
    /// under e.g. <c>varta_client_clock_regression_total</c>.
    /// </summary>
    public ulong ClockRegressions
    {
        get { lock (_lock) { return _clockRegressions; } }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            _disposed = true;
            _transport.Dispose();
        }
    }

    // ---- Test hooks (InternalsVisibleTo Varta.Client.Tests) ----

    internal void SetConnectPidForTest(int pid)
    {
        lock (_lock) { _connectPid = pid; }
    }

    internal ulong NonceForTest
    {
        get { lock (_lock) { return _nonce; } }
        set { lock (_lock) { _nonce = value; } }
    }

    // ---- Helpers ----

    private static ulong SaturatingIncrement(ulong v) => v == ulong.MaxValue ? v : v + 1;
    private static uint SaturatingIncrementU32(uint v) => v == uint.MaxValue ? v : v + 1;
}
