package health.varta.helpers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * Locate the {@code varta-watch} binary for interop tests.
 *
 * <p>Resolution order:
 * <ol>
 *   <li>Environment variable {@code VARTA_WATCH_BIN} (preferred for CI).</li>
 *   <li>{@code <repo-root>/target/release/varta-watch}</li>
 *   <li>{@code <repo-root>/target/debug/varta-watch}</li>
 * </ol>
 */
public final class WatchBinaryLocator {
    private WatchBinaryLocator() {}

    public static Optional<Path> find() throws IOException {
        String env = System.getenv("VARTA_WATCH_BIN");
        if (env != null && !env.isBlank()) {
            Path p = Path.of(env);
            if (Files.isExecutable(p)) return Optional.of(p);
        }
        Path root = RepoRoot.find();
        for (String sub : new String[] {"target/release/varta-watch", "target/debug/varta-watch"}) {
            Path p = root.resolve(sub);
            if (Files.isExecutable(p)) return Optional.of(p);
        }
        return Optional.empty();
    }

    /** JUnit's @EnabledIf-friendly indicator. */
    public static boolean hasWatchBinary() {
        try {
            return find().isPresent();
        } catch (IOException e) {
            return false;
        }
    }
}
