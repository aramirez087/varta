using System.Net;
using System.Net.Sockets;

namespace Varta.Internal.Transport;

/// <summary>
/// Plaintext UDP transport. Dev-only; intended for diagnostics and
/// loopback testing where UDS is not viable. Production deployments
/// should prefer <see cref="UdsTransport"/> (kernel-attested) or
/// <see cref="SecureUdpTransport"/> (AEAD-authenticated).
/// </summary>
internal sealed class UdpTransport : IBeatTransport
{
    private readonly string _host;
    private readonly int _port;
    private Socket _socket;

    public UdpTransport(string host, int port)
    {
        _host = host ?? throw new ArgumentNullException(nameof(host));
        _port = port;
        _socket = BuildConnected(host, port);
    }

    public int Send(ReadOnlySpan<byte> frame) => _socket.Send(frame, SocketFlags.None);

    public void Reconnect()
    {
        var old = _socket;
        _socket = BuildConnected(_host, _port);
        try { old.Dispose(); } catch { /* best-effort */ }
    }

    public void Dispose()
    {
        try { _socket.Dispose(); } catch { /* best-effort */ }
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
}
