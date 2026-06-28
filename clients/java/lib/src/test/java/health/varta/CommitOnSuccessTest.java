package health.varta;

import health.varta.transport.BeatTransport;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Commit-on-success: a Dropped or Failed send must NOT advance the committed
 * nonce/timestamp. A subsequent accepted frame therefore carries the
 * un-burned nonce — the observable proof. Mirrors the Rust regressions in
 * {@code crates/varta-client/src/client.rs::tests} and the Python / Go / Node /
 * .NET equivalents.
 */
class CommitOnSuccessTest {

    /** Drops the first {@code drops} sends, then captures the accepted frame. */
    private static final class DropThenCapture implements BeatTransport {
        int remaining;
        byte[] last;

        DropThenCapture(int drops) {
            this.remaining = drops;
        }

        @Override
        public int send(ByteBuffer frame) {
            if (remaining > 0) {
                remaining--;
                return 0; // Dropped(KERNEL_QUEUE_FULL)
            }
            byte[] copy = new byte[frame.remaining()];
            frame.duplicate().get(copy);
            last = copy;
            return Varta.FRAME_BYTES;
        }

        @Override
        public void reconnect() {
        }

        @Override
        public void close() {
        }
    }

    /** Fails the first send (Failed outcome), then captures the accepted frame. */
    private static final class FailOnceThenCapture implements BeatTransport {
        boolean failed = false;
        byte[] last;

        @Override
        public int send(ByteBuffer frame) throws IOException {
            if (!failed) {
                failed = true;
                throw new IOException("permission denied"); // classified as Failed
            }
            byte[] copy = new byte[frame.remaining()];
            frame.duplicate().get(copy);
            last = copy;
            return Varta.FRAME_BYTES;
        }

        @Override
        public void reconnect() {
        }

        @Override
        public void close() {
        }
    }

    /** Returns a positive short write once, then captures the accepted frame. */
    private static final class ShortOnceThenCapture implements BeatTransport {
        boolean shortened = false;
        byte[] last;

        @Override
        public int send(ByteBuffer frame) {
            if (!shortened) {
                shortened = true;
                return Varta.FRAME_BYTES - 1;
            }
            byte[] copy = new byte[frame.remaining()];
            frame.duplicate().get(copy);
            last = copy;
            return Varta.FRAME_BYTES;
        }

        @Override
        public void reconnect() {
        }

        @Override
        public void close() {
        }
    }

    private static final class CountingTransport implements BeatTransport {
        int sends = 0;
        int reconnects = 0;

        @Override
        public int send(ByteBuffer frame) {
            sends++;
            return Varta.FRAME_BYTES;
        }

        @Override
        public void reconnect() {
            reconnects++;
        }

        @Override
        public void close() {
        }
    }

    @Test
    void droppedBeatsDoNotBurnNonce_firstAcceptedFrameCarriesNonceOne() {
        DropThenCapture t = new DropThenCapture(2);
        Varta agent = Varta.__forTest(t);
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Dropped.class);
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Dropped.class);
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Sent.class);
        assertThat(t.last).isNotNull();
        assertThat(Frame.decode(t.last).nonce()).isEqualTo(1L);
    }

    @Test
    void failedBeatDoesNotBurnNonce() {
        FailOnceThenCapture t = new FailOnceThenCapture();
        Varta agent = Varta.__forTest(t);
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Failed.class);
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Sent.class);
        assertThat(Frame.decode(t.last).nonce()).isEqualTo(1L);
    }

    @Test
    void shortSuccessfulSendDoesNotBurnNonce() {
        ShortOnceThenCapture t = new ShortOnceThenCapture();
        Varta agent = Varta.__forTest(t);

        assertThat(agent.beat(Status.OK))
            .isInstanceOfSatisfying(BeatOutcome.Failed.class,
                f -> assertThat(f.error().kind()).isEqualTo("WriteZero"));
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Sent.class);
        assertThat(Frame.decode(t.last).nonce()).isEqualTo(1L);
    }

    @Test
    void nullStatusReturnsFailedInvalidInputWithoutTransportSideEffects() {
        CountingTransport t = new CountingTransport();
        Varta agent = Varta.__forTest(t);
        agent.setReconnectAfter(1);

        assertThat(agent.beat(null, 0))
            .isInstanceOfSatisfying(BeatOutcome.Failed.class,
                f -> assertThat(f.error().kind()).isEqualTo("InvalidInput"));
        assertThat(t.sends).isZero();
        assertThat(t.reconnects).isZero();
        assertThat(agent.__getNonceForTest()).isEqualTo(Varta.NONCE_MIN);
    }

    @Test
    void reconnectRetryCommitsNonceOnlyOnSuccessfulRetry() {
        DropThenCapture t = new DropThenCapture(2);
        Varta agent = Varta.__forTest(t);
        agent.setReconnectAfter(2);
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Dropped.class);
        // The second drop crosses the threshold; reconnect (no-op) succeeds and
        // the retry sends, committing the un-burned nonce 1.
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Sent.class);
        assertThat(Frame.decode(t.last).nonce()).isEqualTo(1L);
    }

    @Test
    void explicitReconnectPreservesCommittedNonce() {
        DropThenCapture t = new DropThenCapture(0);
        Varta agent = Varta.__forTest(t);

        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Sent.class);
        assertThat(Frame.decode(t.last).nonce()).isEqualTo(1L);

        agent.reconnect();

        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Sent.class);
        assertThat(Frame.decode(t.last).nonce()).isEqualTo(2L);
    }
}
