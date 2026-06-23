using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Varta.Internal.VlpSecure;

namespace Varta.Internal.Transport;

internal enum SecureUdpMode { Shared, Master }

/// <summary>
/// ChaCha20-Poly1305 AEAD UDP transport. Wraps every outbound 32-byte
/// VLP frame into either a 60-byte shared-key wire frame or a 64-byte
/// master-key wire frame (with agent_pid as AAD).
/// </summary>
/// <remarks>
/// <para>
/// Counter advance is <b>commit-on-success</b> — the AEAD IV counter
/// is only persisted after <see cref="Socket.Send(ReadOnlySpan{byte}, SocketFlags)"/>
/// returns. A <see cref="SocketError.WouldBlock"/> retry safely reuses
/// the same nonce.
/// </para>
/// <para>
/// IV-prefix rotation: when the per-prefix counter wraps from
/// <c>uint.MaxValue</c>, the prefix index is bumped and a fresh
/// 8-byte prefix is derived via <c>derive_iv_prefix</c> from the
/// session salt. Zero syscalls, zero blocking — the rotation never
/// touches the OS RNG. The session salt itself is only re-read on
/// <see cref="Reconnect"/>.
/// </para>
/// </remarks>
internal sealed class SecureUdpTransport : IBeatTransport
{
    private readonly SecureUdpMode _mode;
    private readonly string _host;
    private readonly int _port;
    private readonly byte[] _key; // shared key (Shared) or master key (Master), 32 B

    private Socket _socket;
    private readonly byte[] _sessionSalt = new byte[Hkdf.SessionSaltBytes];
    private readonly byte[] _ivPrefix = new byte[Hkdf.IvRandomBytes];
    private uint _prefixIndex;
    private uint _counter;
    private Func<int, int>? _sendResultOverrideForTest;

    public SecureUdpTransport(SecureUdpMode mode, string host, int port, ReadOnlySpan<byte> key32)
    {
        if (key32.Length != Hkdf.KeyBytes)
        {
            throw new ArgumentException($"key must be {Hkdf.KeyBytes} bytes", nameof(key32));
        }
        if (!ChaCha20Poly1305.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "ChaCha20-Poly1305 is not available on this platform / .NET runtime. " +
                "Secure UDP requires .NET 6+ on Linux/Windows or .NET 7+ on macOS.");
        }

        _mode = mode;
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _port = port;
        _key = key32.ToArray();

        _socket = BuildConnected(host, port);
        RefreshIvState();
    }

    public int Send(ReadOnlySpan<byte> plaintext32)
    {
        if (plaintext32.Length != AeadCodec.PlaintextBytes)
        {
            throw new ArgumentException($"plaintext must be {AeadCodec.PlaintextBytes} bytes", nameof(plaintext32));
        }

        // Reserve a counter value WITHOUT committing it — commit on send success.
        uint pendingCounter = _counter;

        int sent;
        int expectedWireBytes;
        if (_mode == SecureUdpMode.Shared)
        {
            Span<byte> wire = stackalloc byte[AeadCodec.SharedFrameBytes];
            AeadCodec.EncodeShared(_key, _ivPrefix, pendingCounter, plaintext32, wire);
            sent = SendWire(wire);
            expectedWireBytes = AeadCodec.SharedFrameBytes;
        }
        else // Master
        {
            Span<byte> wire = stackalloc byte[AeadCodec.MasterFrameBytes];
            Span<byte> derived = stackalloc byte[Hkdf.KeyBytes];
            uint agentPid = (uint)Environment.ProcessId;
            try
            {
                AeadCodec.EncodeMaster(_key, agentPid, _ivPrefix, pendingCounter, plaintext32, wire, derived);
                sent = SendWire(wire);
                expectedWireBytes = AeadCodec.MasterFrameBytes;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(derived);
            }
        }

        if (sent != expectedWireBytes)
        {
            return 0;
        }

        // Commit counter advance only after the full encrypted datagram is accepted.
        if (pendingCounter == uint.MaxValue)
        {
            // Counter wrap — rotate the IV prefix index and re-derive.
            _prefixIndex++;
            _counter = 0;
            Hkdf.DeriveIvPrefix(_sessionSalt, _prefixIndex, _ivPrefix);
        }
        else
        {
            _counter = pendingCounter + 1;
        }

        return AeadCodec.PlaintextBytes;
    }

    public void Reconnect()
    {
        // Build new state in locals first; commit without `?`/error
        // propagation between the salt read and the IV derivation
        // (matches the Rust SecureUdpTransport::reconnect transactional
        // pattern — cerebrum 2026-05-15).
        var newSocket = BuildConnected(_host, _port);
        var newSalt = new byte[Hkdf.SessionSaltBytes];
        RandomNumberGenerator.Fill(newSalt);
        var newPrefix = new byte[Hkdf.IvRandomBytes];
        Hkdf.DeriveIvPrefix(newSalt, prefixIndex: 0, newPrefix);

        var old = _socket;
        _socket = newSocket;
        newSalt.CopyTo(_sessionSalt, 0);
        newPrefix.CopyTo(_ivPrefix, 0);
        _prefixIndex = 0;
        _counter = 0;
        try { old.Dispose(); } catch { /* best-effort */ }
    }

    public void Dispose()
    {
        try { _socket.Dispose(); } catch { /* best-effort */ }
        CryptographicOperations.ZeroMemory(_key);
        CryptographicOperations.ZeroMemory(_sessionSalt);
        CryptographicOperations.ZeroMemory(_ivPrefix);
    }

    private void RefreshIvState()
    {
        RandomNumberGenerator.Fill(_sessionSalt);
        _prefixIndex = 0;
        _counter = 0;
        Hkdf.DeriveIvPrefix(_sessionSalt, _prefixIndex, _ivPrefix);
    }

    private static Socket BuildConnected(string host, int port)
    {
        var addresses = Dns.GetHostAddresses(host);
        if (addresses.Length == 0)
        {
            throw new SocketException((int)SocketError.HostNotFound);
        }
        var addr = addresses[0];
        var family = addr.AddressFamily == AddressFamily.InterNetworkV6
            ? AddressFamily.InterNetworkV6
            : AddressFamily.InterNetwork;
        var socket = new Socket(family, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Connect(new IPEndPoint(addr, port));
            socket.Blocking = false;
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private int SendWire(ReadOnlySpan<byte> wire) =>
        _sendResultOverrideForTest is not null
            ? _sendResultOverrideForTest(wire.Length)
            : _socket.Send(wire, SocketFlags.None);

    // ---- Test hooks (InternalsVisibleTo Varta.Client.Tests) ----

    internal void SetSendResultOverrideForTest(Func<int, int>? sendResultOverride) =>
        _sendResultOverrideForTest = sendResultOverride;

    internal uint PrefixIndexForTest => _prefixIndex;

    internal uint CounterForTest
    {
        get => _counter;
        set => _counter = value;
    }

    internal byte[] IvPrefixForTest => _ivPrefix.ToArray();
}
