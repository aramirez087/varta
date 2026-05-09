package health.varta.examples;

import health.varta.BeatOutcome;
import health.varta.Status;
import health.varta.Varta;

import java.nio.file.Path;
import java.nio.file.Paths;

/** Minimal beat loop over UDS. Mirrors {@code crates/varta-client/examples/basic.rs}. */
public final class BasicUds {
    private BasicUds() {}

    public static void main(String[] args) throws InterruptedException {
        Path socket = Paths.get(args.length > 0 ? args[0] : "/run/varta/observer.sock");
        try (Varta agent = Varta.connect(socket)) {
            System.out.println("[basic-uds] connected to " + socket + "; emitting Status.OK every 500 ms");
            while (!Thread.currentThread().isInterrupted()) {
                BeatOutcome outcome = agent.beat(Status.OK);
                if (outcome.isDropped()) {
                    System.err.println("[basic-uds] dropped: " + outcome);
                }
                Thread.sleep(500);
            }
        }
    }
}
