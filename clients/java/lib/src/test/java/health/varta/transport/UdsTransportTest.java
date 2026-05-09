package health.varta.transport;

import health.varta.helpers.TmpUds;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.newsclub.net.unix.AFUNIXDatagramChannel;
import org.newsclub.net.unix.AFUNIXSocketAddress;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledOnOs({ OS.LINUX, OS.MAC })
class UdsTransportTest {

    @Test
    void send_delivers_one_frame_to_local_recorder() throws Exception {
        Path sock = TmpUds.allocate();
        try (AFUNIXDatagramChannel recorder = AFUNIXDatagramChannel.open()) {
            recorder.bind(AFUNIXSocketAddress.of(sock.toFile()));
            recorder.configureBlocking(true);

            try (BeatTransport tx = UdsTransport.create(sock)) {
                byte[] payload = new byte[32];
                for (int i = 0; i < 32; i++) payload[i] = (byte) (i * 7);
                int sent = tx.send(ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN));
                assertThat(sent).isEqualTo(32);

                ByteBuffer received = ByteBuffer.allocate(64);
                recorder.receive(received);
                received.flip();
                byte[] got = new byte[received.remaining()];
                received.get(got);
                assertThat(Arrays.copyOf(got, 32)).isEqualTo(payload);
            }
        } finally {
            Files.deleteIfExists(sock);
        }
    }
}
