package health.varta.transport;

import health.varta.BeatOutcome;
import health.varta.DropReason;
import health.varta.errno.ErrnoClassifier;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;

import static org.assertj.core.api.Assertions.assertThat;

class ErrnoClassifierTest {

    @Test
    void port_unreachable_is_no_observer() {
        BeatOutcome o = ErrnoClassifier.classify(new PortUnreachableException("ICMP unreachable"));
        assertThat(o).isInstanceOfSatisfying(BeatOutcome.Dropped.class,
            d -> assertThat(d.reason()).isEqualTo(DropReason.NO_OBSERVER));
    }

    @Test
    void closed_channel_is_peer_gone() {
        BeatOutcome o = ErrnoClassifier.classify(new ClosedChannelException());
        assertThat(o).isInstanceOfSatisfying(BeatOutcome.Dropped.class,
            d -> assertThat(d.reason()).isEqualTo(DropReason.PEER_GONE));
    }

    @Test
    void no_buffer_space_message_is_kernel_queue_full() {
        BeatOutcome o = ErrnoClassifier.classify(new SocketException("No buffer space available"));
        assertThat(o).isInstanceOfSatisfying(BeatOutcome.Dropped.class,
            d -> assertThat(d.reason()).isEqualTo(DropReason.KERNEL_QUEUE_FULL));
    }

    @Test
    void solaris_illumos_enobufs_errno_is_kernel_queue_full() throws Exception {
        assertThat(mapErrno(132)).isEqualTo(DropReason.KERNEL_QUEUE_FULL);
    }

    @Test
    void connection_refused_is_no_observer() {
        BeatOutcome o = ErrnoClassifier.classify(new SocketException("Connection refused"));
        assertThat(o).isInstanceOfSatisfying(BeatOutcome.Dropped.class,
            d -> assertThat(d.reason()).isEqualTo(DropReason.NO_OBSERVER));
    }

    @Test
    void broken_pipe_is_peer_gone() {
        BeatOutcome o = ErrnoClassifier.classify(new SocketException("Broken pipe"));
        assertThat(o).isInstanceOfSatisfying(BeatOutcome.Dropped.class,
            d -> assertThat(d.reason()).isEqualTo(DropReason.PEER_GONE));
    }

    @Test
    void no_space_left_is_storage_full() {
        BeatOutcome o = ErrnoClassifier.classify(new IOException("No space left on device"));
        assertThat(o).isInstanceOfSatisfying(BeatOutcome.Dropped.class,
            d -> assertThat(d.reason()).isEqualTo(DropReason.STORAGE_FULL));
    }

    @Test
    void unknown_message_is_failed_not_dropped() {
        BeatOutcome o = ErrnoClassifier.classify(new IOException("totally novel failure"));
        assertThat(o).isInstanceOf(BeatOutcome.Failed.class);
    }

    @Test
    void write_zero_message_preserves_stable_error_kind() {
        BeatOutcome o = ErrnoClassifier.classify(new IOException("WriteZero"));
        assertThat(o).isInstanceOfSatisfying(BeatOutcome.Failed.class,
            f -> assertThat(f.error().kind()).isEqualTo("WriteZero"));
    }

    private static DropReason mapErrno(int errno) throws Exception {
        Method method = ErrnoClassifier.class.getDeclaredMethod("mapErrno", int.class);
        method.setAccessible(true);
        return (DropReason) method.invoke(null, errno);
    }
}
