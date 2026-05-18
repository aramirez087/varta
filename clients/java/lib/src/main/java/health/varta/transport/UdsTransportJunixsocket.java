package health.varta.transport;

import org.newsclub.net.unix.AFUNIXDatagramChannel;
import org.newsclub.net.unix.AFUNIXSocketAddress;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;

/**
 * UDS provider backed by <a href="https://kohlschutter.github.io/junixsocket/">junixsocket</a>.
 *
 * <p>Selected reflectively by {@link UdsTransport} when
 * {@code org.newsclub.net.unix.AFUNIXSocketAddress} is on the classpath
 * and no FFM provider is available. junixsocket ships bundled native libs
 * for Linux x86_64/aarch64, macOS x86_64/aarch64, and Windows 10 1803+.</p>
 */
final class UdsTransportJunixsocket implements BeatTransport {
    private final AFUNIXSocketAddress addr;
    private AFUNIXDatagramChannel channel;

    private UdsTransportJunixsocket(AFUNIXSocketAddress addr, AFUNIXDatagramChannel channel) {
        this.addr = addr;
        this.channel = channel;
    }

    static UdsTransportJunixsocket create(Path socketPath) throws IOException {
        AFUNIXSocketAddress a = AFUNIXSocketAddress.of(socketPath.toFile());
        AFUNIXDatagramChannel ch = open(a);
        return new UdsTransportJunixsocket(a, ch);
    }

    private static AFUNIXDatagramChannel open(AFUNIXSocketAddress addr) throws IOException {
        AFUNIXDatagramChannel ch = AFUNIXDatagramChannel.open();
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
        AFUNIXDatagramChannel old = channel;
        channel = open(addr);
        try { old.close(); } catch (IOException ignored) {}
    }

    @Override
    public void close() {
        try { channel.close(); } catch (IOException ignored) {}
    }
}
