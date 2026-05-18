package health.varta.transport;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.Objects;

/**
 * Non-blocking UDP transport. Used for loopback / LAN deployments and on
 * Windows where AF_UNIX SOCK_DGRAM isn't available.
 *
 * <p>The observer sees these beats as {@code BeatOrigin::NetworkUnverified}
 * and refuses to fire recovery commands. For recovery-eligible same-host
 * deployments, use {@code UdsTransport} instead.</p>
 */
public final class UdpTransport implements BeatTransport {
    private final InetSocketAddress addr;
    private DatagramChannel channel;

    private UdpTransport(InetSocketAddress addr, DatagramChannel channel) {
        this.addr = addr;
        this.channel = channel;
    }

    public static UdpTransport create(InetSocketAddress addr) throws IOException {
        Objects.requireNonNull(addr, "addr");
        DatagramChannel ch = open(addr);
        return new UdpTransport(addr, ch);
    }

    private static DatagramChannel open(InetSocketAddress addr) throws IOException {
        StandardProtocolFamily fam = addr.getAddress() != null && addr.getAddress() instanceof java.net.Inet6Address
            ? StandardProtocolFamily.INET6 : StandardProtocolFamily.INET;
        DatagramChannel ch = DatagramChannel.open(fam);
        try {
            ch.configureBlocking(false);
            ch.connect(addr);
            return ch;
        } catch (IOException e) {
            try { ch.close(); } catch (IOException ignored) {}
            throw e;
        }
    }

    @Override
    public int send(ByteBuffer frame) throws IOException {
        return channel.write(frame);
    }

    @Override
    public void reconnect() throws IOException {
        DatagramChannel old = channel;
        channel = open(addr);
        try { old.close(); } catch (IOException ignored) {}
    }

    @Override
    public void close() {
        try { channel.close(); } catch (IOException ignored) {}
    }
}
