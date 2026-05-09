using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Varta.Internal.Transport;

/// <summary>
/// Unix Domain Socket transport (<c>AF_UNIX</c> + <c>SOCK_DGRAM</c>).
/// Linux and macOS only — Windows lacks BCL support for SOCK_DGRAM AF_UNIX
/// and the constructor throws <see cref="PlatformNotSupportedException"/>
/// there.
/// </summary>
internal sealed class UdsTransport : IBeatTransport
{
    private readonly string _path;
    private Socket _socket;

    public UdsTransport(string socketPath)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            throw new PlatformNotSupportedException(
                "UDS (AF_UNIX SOCK_DGRAM) is not supported on Windows. " +
                "Use Varta.ConnectUdp(\"127.0.0.1\", port) or " +
                "Varta.ConnectSecureUdp(...) instead.");
        }

        _path = socketPath ?? throw new ArgumentNullException(nameof(socketPath));
        _socket = BuildConnected(_path);
    }

    public int Send(ReadOnlySpan<byte> frame32) => _socket.Send(frame32, SocketFlags.None);

    public void Reconnect()
    {
        var old = _socket;
        _socket = BuildConnected(_path);
        try { old.Dispose(); } catch { /* best-effort */ }
    }

    public void Dispose()
    {
        try { _socket.Dispose(); } catch { /* best-effort */ }
    }

    private static Socket BuildConnected(string path)
    {
        var socket = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
        try
        {
            socket.Connect(new UnixDomainSocketEndPoint(path));
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
