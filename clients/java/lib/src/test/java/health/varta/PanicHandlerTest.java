package health.varta;

import health.varta.panic.SignalHandler;
import org.junit.jupiter.api.Test;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

class PanicHandlerTest {

    @Test
    void install_shutdown_hook_pre_binds_transport_without_throwing() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
             AutoCloseable hook = SignalHandler.installShutdownHookUdp(
                 new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort()))) {
            assertThat(hook).isNotNull();
        }
    }

    @Test
    void run_emits_critical_then_rethrows() throws Exception {
        try (DatagramSocket rec = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0))) {
            InetSocketAddress addr = new InetSocketAddress(InetAddress.getLoopbackAddress(), rec.getLocalPort());

            try (AutoCloseable hook = SignalHandler.installShutdownHookUdp(addr)) {
                try {
                    SignalHandler.run(() -> { throw new IllegalStateException("boom"); });
                } catch (IllegalStateException expected) {
                    assertThat(expected).hasMessageContaining("boom");
                }
            }

            rec.setSoTimeout(2000);
            DatagramPacket pkt = new DatagramPacket(new byte[64], 64);
            rec.receive(pkt);
            assertThat(pkt.getLength()).isEqualTo(Varta.FRAME_BYTES);
            Frame frame = Frame.decode(java.util.Arrays.copyOf(pkt.getData(), pkt.getLength()));
            assertThat(frame.status()).isEqualTo(Status.CRITICAL);
            assertThat(frame.nonce()).isEqualTo(Varta.NONCE_TERMINAL);
        }
    }

    @Test
    void install_fails_closed_when_uds_path_is_invalid(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp) {
        // UDS connect to a directory path → IOException → wrapped as PanicInstallException.
        // Skip gracefully if no UDS provider is on the classpath (test infrastructure issue,
        // not a contract violation).
        try {
            SignalHandler.installShutdownHookUds(tmp); // tmp is a directory
            org.junit.jupiter.api.Assertions.fail("expected PanicInstallException");
        } catch (PanicInstallException expected) {
            assertThat(expected.getMessage()).contains("could not pre-bind");
        } catch (IllegalStateException unsupported) {
            // No UDS provider — surfaces as IllegalStateException from Varta.connect path
            // (PanicHandler.installShutdownHookUds → UdsTransport.create wraps as IOException
            // then PanicInstallException, so this branch only fires on classpath misconfig).
            org.junit.jupiter.api.Assumptions.abort("no UDS provider on classpath: " + unsupported.getMessage());
        }
    }
}
