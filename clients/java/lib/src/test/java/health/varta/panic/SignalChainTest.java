package health.varta.panic;

import health.varta.transport.BeatTransport;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression: the POSIX signal handler must emit the terminal beat and then
 * RESTORE and re-raise to the handler that was installed before Varta's,
 * instead of forcing {@code System.exit()} — which silently clobbered the
 * host's own {@code sun.misc.Signal} handler (the JVM sibling of the Node
 * {@code removeAllListeners} bug, bug-481). All peer clients chain/re-raise to
 * the previous handler.
 */
class SignalChainTest {

    private static final class RecordingTransport implements BeatTransport {
        final List<byte[]> sent = new ArrayList<>();

        @Override
        public int send(ByteBuffer frame) {
            byte[] copy = new byte[frame.remaining()];
            frame.duplicate().get(copy);
            sent.add(copy);
            return copy.length;
        }

        @Override
        public void reconnect() {
        }

        @Override
        public void close() {
        }
    }

    @Test
    void terminating_signal_restores_previous_handler_and_reraises() {
        sun.misc.Signal term = new sun.misc.Signal("TERM");
        // Snapshot the live handler so the test leaves the JVM as it found it.
        sun.misc.SignalHandler original = sun.misc.Signal.handle(term, sun.misc.SignalHandler.SIG_DFL);
        try {
            // A sentinel standing in for a host-installed signal handler that
            // must survive Varta's handler and still run on the signal.
            sun.misc.SignalHandler sentinel = s -> {
            };
            RecordingTransport tx = new RecordingTransport();
            Emitter emitter = new Emitter(tx);
            List<sun.misc.Signal> reRaised = new ArrayList<>();

            SignalHandler.onTerminatingSignal(term, sentinel, emitter, reRaised::add);

            // 1) Exactly one terminal beat was emitted.
            assertThat(tx.sent).hasSize(1);
            // 2) The previously-installed (sentinel) handler is restored, NOT
            //    clobbered. handle() returns the current handler, which must be
            //    the sentinel — proving Varta chained to it rather than exiting.
            sun.misc.SignalHandler current = sun.misc.Signal.handle(term, sentinel);
            assertThat(current).isSameAs(sentinel);
            // 3) The signal is re-raised so the restored handler / default
            //    disposition runs, instead of the process being force-exited.
            assertThat(reRaised).containsExactly(term);
        } finally {
            sun.misc.Signal.handle(term, original);
        }
    }
}
