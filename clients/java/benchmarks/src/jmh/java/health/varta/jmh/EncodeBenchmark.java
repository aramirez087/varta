package health.varta.jmh;

import health.varta.Status;
import health.varta.vlp.Codec;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32C;

/** Measure {@link Codec#encodeInto} in isolation. Target: zero allocation per op. */
@BenchmarkMode({ Mode.AverageTime, Mode.SingleShotTime })
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
@State(Scope.Thread)
public class EncodeBenchmark {

    private ByteBuffer scratch;
    private CRC32C crc;
    private long nonce = 1L;

    @Setup
    public void setup() {
        scratch = ByteBuffer.allocate(Codec.FRAME_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        crc = new CRC32C();
    }

    @Benchmark
    public void encode_one_frame(Blackhole bh) {
        Codec.encodeInto(scratch, Status.OK, 4242, System.nanoTime(), nonce++, 0, crc);
        bh.consume(scratch.array());
    }
}
