package health.varta.helpers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Allocate a short, unique UDS path within the system tmp dir.
 *
 * <p>macOS limits {@code sun_path} to 104 bytes. {@link Files#createTempFile}
 * + {@link Path#toAbsolutePath()} occasionally exceeds that on CI runners
 * with deep user-home paths. We hand-construct a sub-50-char path under
 * {@code /tmp/} (or {@code /var/folders/...} short-form) to stay well clear.</p>
 */
public final class TmpUds {
    private static final AtomicInteger COUNTER = new AtomicInteger();

    private TmpUds() {}

    public static Path allocate() throws IOException {
        Path tmp = Path.of("/tmp");
        if (!Files.isDirectory(tmp)) {
            tmp = Path.of(System.getProperty("java.io.tmpdir"));
        }
        String name = String.format("vt-%d-%d.sock",
            ProcessHandle.current().pid(), COUNTER.incrementAndGet());
        Path p = tmp.resolve(name);
        try { Files.deleteIfExists(p); } catch (IOException ignored) {}
        return p;
    }
}
