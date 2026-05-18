package health.varta.jmh;

import health.varta.Status;
import health.varta.Varta;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

/**
 * End-to-end {@code beat()} cost over a loopback UDP recorder. Run with
 * {@code -prof gc} to verify the alloc-rate claim documented in README.
 */
@BenchmarkMode({ Mode.AverageTime, Mode.SingleShotTime })
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
@State(Scope.Thread)
public class BeatLatencyBenchmark {

    private DatagramSocket recorder;
    private Varta agent;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        recorder = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0));
        agent = Varta.connectUdp(
            new InetSocketAddress(InetAddress.getLoopbackAddress(), recorder.getLocalPort()));
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        agent.close();
        recorder.close();
    }

    @Benchmark
    public void beat_ok(Blackhole bh) {
        bh.consume(agent.beat(Status.OK, 0));
    }
}
