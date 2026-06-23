namespace Varta.Internal.Transport;

/// <summary>
/// Hot-path abstraction over the wire — implemented by UDS, plaintext
/// UDP, and secure UDP transports. The contract is:
/// <list type="bullet">
///   <item><see cref="Send"/> is non-blocking. A full kernel buffer
///     surfaces as a <see cref="System.Net.Sockets.SocketException"/>
///     with <see cref="System.Net.Sockets.SocketError.WouldBlock"/>;
///     the caller is responsible for classifying that as a dropped
///     beat rather than retrying.</item>
///   <item><see cref="Reconnect"/> rebuilds the underlying socket. May
///     allocate. For secure transports it also refreshes the IV
///     session salt from OS entropy.</item>
///   <item><see cref="System.IDisposable.Dispose"/> closes the socket.</item>
/// </list>
/// </summary>
internal interface IBeatTransport : IDisposable
{
    /// <summary>
    /// Emit one VLP frame. Returns <c>Varta.FrameBytes</c> only after a
    /// full logical heartbeat is accepted; any other return value is treated as
    /// <c>Failed(WriteZero)</c>. Throws <see cref="System.Net.Sockets.SocketException"/>
    /// on kernel-level failure.
    /// </summary>
    int Send(ReadOnlySpan<byte> frame32);

    /// <summary>
    /// Rebuild the socket. Called after fork(2) detection or after the
    /// caller-configured "reconnect after N drops" threshold trips.
    /// </summary>
    void Reconnect();
}
