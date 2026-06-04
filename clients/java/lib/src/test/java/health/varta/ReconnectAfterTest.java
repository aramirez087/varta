package health.varta;

import health.varta.transport.BeatTransport;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code setReconnectAfter} must reconnect after N consecutive <em>Dropped</em>
 * beats (observer-restart recovery) — never after N healthy beats. Regression
 * for the inverted {@code sinceReconnect} semantics that reconnected on the
 * healthy path and never recovered from a sustained outage.
 */
class ReconnectAfterTest {

    /** Records reconnect() calls; the send() outcome is scripted. */
    private static final class FakeTransport implements BeatTransport {
        int reconnectCalls = 0;
        final boolean drop;

        FakeTransport(boolean drop) {
            this.drop = drop;
        }

        @Override
        public int send(ByteBuffer frame) {
            // 0 → Dropped(KERNEL_QUEUE_FULL); FRAME_BYTES → Sent.
            return drop ? 0 : Varta.FRAME_BYTES;
        }

        @Override
        public void reconnect() {
            reconnectCalls++;
        }

        @Override
        public void close() {
        }
    }

    @Test
    void reconnect_fires_after_n_consecutive_drops() {
        FakeTransport t = new FakeTransport(true);
        Varta agent = Varta.__forTest(t);
        agent.setReconnectAfter(3);

        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Dropped.class);
        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Dropped.class);
        assertThat(t.reconnectCalls)
            .as("must not reconnect before the threshold")
            .isZero();

        assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Dropped.class);
        assertThat(t.reconnectCalls)
            .as("the third consecutive drop crosses the threshold and reconnects")
            .isEqualTo(1);
    }

    @Test
    void healthy_beats_never_trigger_reconnect() {
        FakeTransport t = new FakeTransport(false);
        Varta agent = Varta.__forTest(t);
        agent.setReconnectAfter(3);

        for (int i = 0; i < 10; i++) {
            assertThat(agent.beat(Status.OK)).isInstanceOf(BeatOutcome.Sent.class);
        }
        assertThat(t.reconnectCalls)
            .as("healthy beats must not churn the socket — drop-recovery is for drops only")
            .isZero();
    }
}
