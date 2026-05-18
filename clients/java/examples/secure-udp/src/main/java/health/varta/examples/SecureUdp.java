package health.varta.examples;

import health.varta.Key;
import health.varta.Status;
import health.varta.Varta;

import java.net.InetSocketAddress;
import java.util.HexFormat;

/** ChaCha20-Poly1305 AEAD beats over UDP. */
public final class SecureUdp {
    private SecureUdp() {}

    public static void main(String[] args) throws InterruptedException {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 9443;
        String keyHex = args.length > 2 ? args[2]
            : "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        Key key = Key.fromBytes(HexFormat.of().parseHex(keyHex));
        try (Varta agent = Varta.connectSecureUdp(new InetSocketAddress(host, port), key)) {
            while (!Thread.currentThread().isInterrupted()) {
                agent.beat(Status.OK);
                Thread.sleep(500);
            }
        } finally {
            key.zeroize();
        }
    }
}
