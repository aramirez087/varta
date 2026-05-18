package health.varta;

import health.varta.helpers.TmpUds;
import health.varta.helpers.WatchBinaryLocator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledOnOs({ OS.LINUX, OS.MAC })
@EnabledIf("health.varta.helpers.WatchBinaryLocator#hasWatchBinary")
class InteropObserverTest {

    private static final String PROM_TOKEN_HEX =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @Test
    @Timeout(value = 90, unit = TimeUnit.SECONDS)
    void java_agent_beats_visible_in_metrics() throws Exception {
        Path watch = WatchBinaryLocator.find().orElseThrow();
        Path uds = TmpUds.allocate();
        Path tokenFile = Files.writeString(Files.createTempFile("varta-tok-", ".txt"), PROM_TOKEN_HEX);
        try {
            Files.setPosixFilePermissions(tokenFile,
                PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) { /* non-POSIX FS */ }

        ProcessBuilder pb = new ProcessBuilder(
            watch.toString(),
            "--socket", uds.toString(),
            "--threshold-ms", "10000",
            "--prom-addr", "127.0.0.1:0",
            "--prom-token-file", tokenFile.toString(),
            "--prom-rate-limit-burst", "0",
            "--shutdown-after-secs", "60")
            .redirectErrorStream(true);

        Process proc = pb.start();
        String promAuthority;
        try {
            promAuthority = readBoundPromAddr(proc.getInputStream());
            awaitFile(uds, 5_000);

            try (Varta agent = Varta.connect(uds)) {
                int sent = 0;
                for (int i = 0; i < 50; i++) {
                    BeatOutcome o = agent.beat(Status.OK, 0);
                    if (o instanceof BeatOutcome.Sent) {
                        sent++;
                    } else if (o instanceof BeatOutcome.Dropped d
                        && d.reason() == DropReason.KERNEL_QUEUE_FULL) {
                        Thread.sleep(1);
                    } else if (o instanceof BeatOutcome.Failed f) {
                        throw new AssertionError("beat failed: " + f.error());
                    }
                }
                assertThat(sent).isGreaterThanOrEqualTo(10);
            }

            Thread.sleep(500);
            String body = scrapeMetrics(promAuthority);
            assertThat(body)
                .as("prometheus body for %s", promAuthority)
                .contains("varta_");
            assertThat(anyNonZeroVartaMetric(body))
                .as("at least one varta_* metric should be non-zero. body=\n%s", body)
                .isTrue();
        } finally {
            try {
                proc.destroy();
                proc.waitFor(5, TimeUnit.SECONDS);
                if (proc.isAlive()) proc.destroyForcibly();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            try { Files.deleteIfExists(uds); } catch (IOException ignored) {}
            try { Files.deleteIfExists(tokenFile); } catch (IOException ignored) {}
        }
    }

    private static String readBoundPromAddr(InputStream stdout) throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(stdout, StandardCharsets.UTF_8));
        long deadline = System.currentTimeMillis() + 10_000;
        while (System.currentTimeMillis() < deadline) {
            String line = r.readLine();
            if (line == null) {
                throw new IOException("varta-watch stdout closed before printing prom addr");
            }
            String trimmed = line.trim();
            if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                trimmed = trimmed.substring(1, trimmed.length() - 1);
            }
            if (trimmed.matches("[0-9.]+:[0-9]+")) {
                return trimmed;
            }
            // diagnostic logging lines, skip
        }
        throw new IOException("varta-watch did not print prom addr within 10 s");
    }

    private static void awaitFile(Path p, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (Files.exists(p)) return;
            Thread.sleep(10);
        }
        throw new AssertionError("socket file did not appear at " + p);
    }

    private static String scrapeMetrics(String authority) throws IOException {
        // varta-watch's hand-rolled HTTP/1.0 parser is fussy; bypass HttpClient
        // and write the request bytes directly (matches the .NET interop test).
        int colon = authority.lastIndexOf(':');
        String host = authority.substring(0, colon);
        int port = Integer.parseInt(authority.substring(colon + 1));

        try (Socket sock = new Socket()) {
            sock.connect(new InetSocketAddress(host, port), 5_000);
            sock.setSoTimeout(5_000);
            String request =
                "GET /metrics HTTP/1.0\r\n" +
                "Host: " + authority + "\r\n" +
                "Authorization: Bearer " + PROM_TOKEN_HEX + "\r\n" +
                "Connection: close\r\n" +
                "\r\n";
            sock.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            sock.getOutputStream().flush();

            byte[] all = sock.getInputStream().readAllBytes();
            String raw = new String(all, StandardCharsets.UTF_8);
            int hdrEnd = raw.indexOf("\r\n\r\n");
            if (hdrEnd < 0) throw new IOException("no header/body separator in response");
            String body = raw.substring(hdrEnd + 4);
            int statusEnd = raw.indexOf("\r\n");
            String statusLine = statusEnd < 0 ? raw : raw.substring(0, statusEnd);
            if (!statusLine.contains(" 200 ")) {
                throw new IOException("non-200 from /metrics: " + statusLine + "\nbody=\n" + body);
            }
            return body;
        }
    }

    private static boolean anyNonZeroVartaMetric(String body) {
        for (String line : body.split("\n")) {
            if (!line.startsWith("varta_")) continue;
            int sp = line.lastIndexOf(' ');
            if (sp < 0) continue;
            String val = line.substring(sp + 1).trim();
            try {
                double d = Double.parseDouble(val);
                if (d > 0.0) return true;
            } catch (NumberFormatException ignored) {}
        }
        return false;
    }
}
