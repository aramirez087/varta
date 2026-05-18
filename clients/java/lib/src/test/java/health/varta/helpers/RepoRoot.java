package health.varta.helpers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Locate the Varta repository root by walking up from CWD until {@code Cargo.toml} is found. */
public final class RepoRoot {
    private RepoRoot() {}

    public static Path find() throws IOException {
        Path here = Path.of(".").toAbsolutePath().normalize();
        Path cur = here;
        for (int i = 0; i < 8 && cur != null; i++) {
            if (Files.exists(cur.resolve("Cargo.toml"))
                && Files.exists(cur.resolve("clients").resolve("java"))) {
                return cur;
            }
            cur = cur.getParent();
        }
        throw new IOException("could not locate Varta repo root starting from " + here);
    }
}
