using System.Net;
using System.Net.Sockets;

namespace Varta.Tests.Helpers;

/// <summary>
/// Allocates a temporary UDS path short enough for macOS
/// <c>sun_path</c> (104-char limit) and bound to a non-blocking
/// receiver socket the test can read frames from.
/// </summary>
/// <remarks>
/// xUnit's default tmp directory under <c>$TMPDIR</c> can blow through
/// macOS's 104-char <c>sun_path</c> cap. Build under
/// <see cref="Path.GetTempPath"/> directly with a short
/// pid+counter-based stem (cerebrum 2026-05-16).
/// </remarks>
internal static class TmpUds
{
    private static long _seq;

    public static string AllocatePath()
    {
        long n = Interlocked.Increment(ref _seq);
        string name = $"varta-{Environment.ProcessId}-{n}.sock";
        return Path.Combine(Path.GetTempPath(), name);
    }

    /// <summary>
    /// Bind a non-blocking listener socket at <paramref name="path"/>
    /// and return the socket. Caller is responsible for disposing the
    /// socket AND removing the file.
    /// </summary>
    public static Socket BindListener(string path)
    {
        if (File.Exists(path)) File.Delete(path);
        var sock = new Socket(AddressFamily.Unix, SocketType.Dgram, ProtocolType.Unspecified);
        sock.Bind(new UnixDomainSocketEndPoint(path));
        sock.Blocking = false;
        return sock;
    }

    public static bool TryReceive(Socket recv, Span<byte> dest, out int read, int retries = 50, int retryDelayMs = 5)
    {
        for (int i = 0; i < retries; i++)
        {
            try
            {
                read = recv.Receive(dest, SocketFlags.None);
                return true;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.WouldBlock)
            {
                Thread.Sleep(retryDelayMs);
            }
        }
        read = 0;
        return false;
    }
}
