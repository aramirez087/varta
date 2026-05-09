package health.varta.helpers;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Load and project {@code tools/vlp-test-vectors.json} into typed records
 * for parameterized JUnit consumption.
 */
public final class VectorsLoader {
    private final JsonObject root;

    private VectorsLoader(JsonObject root) {
        this.root = root;
    }

    public static VectorsLoader load() {
        try {
            Path file = RepoRoot.find().resolve("tools").resolve("vlp-test-vectors.json");
            JsonElement parsed = JsonParser.parseString(Files.readString(file));
            return new VectorsLoader(parsed.getAsJsonObject());
        } catch (IOException e) {
            throw new IllegalStateException("could not load vlp-test-vectors.json", e);
        }
    }

    public List<CrcVector> crc32cVectors() {
        List<CrcVector> out = new ArrayList<>();
        JsonArray arr = root.getAsJsonArray("crc32c_vectors");
        for (JsonElement el : arr) {
            JsonObject o = el.getAsJsonObject();
            out.add(new CrcVector(
                o.get("id").getAsString(),
                hex(o.get("input_hex").getAsString()),
                Long.parseUnsignedLong(o.get("expected_crc_hex").getAsString(), 16)));
        }
        return out;
    }

    public List<FrameVector> frameVectors() {
        List<FrameVector> out = new ArrayList<>();
        for (JsonElement el : root.getAsJsonArray("frame_vectors")) {
            JsonObject o = el.getAsJsonObject();
            String kind = o.get("kind").getAsString();
            String id = o.get("id").getAsString();
            String error = (o.get("expected_decode_error") == null || o.get("expected_decode_error").isJsonNull())
                ? null : o.get("expected_decode_error").getAsString();
            if ("encode_decode_roundtrip".equals(kind)) {
                JsonObject in = o.getAsJsonObject("inputs");
                out.add(new FrameVector(id, kind, error,
                    in.get("status").getAsString(),
                    in.get("pid").getAsInt(),
                    in.get("timestamp").getAsLong(),
                    in.get("nonce").getAsLong(),
                    in.get("payload").getAsInt(),
                    hex(o.get("expected_wire_hex").getAsString()),
                    null));
            } else {
                out.add(new FrameVector(id, kind, error,
                    null, 0, 0L, 0L, 0,
                    null,
                    hex(o.get("wire_hex").getAsString())));
            }
        }
        return out;
    }

    public List<SecureVector> secureFrameVectors() {
        List<SecureVector> out = new ArrayList<>();
        for (JsonElement el : root.getAsJsonArray("secure_frame_vectors")) {
            JsonObject o = el.getAsJsonObject();
            out.add(new SecureVector(
                o.get("id").getAsString(),
                o.get("kind").getAsString(),
                hexOrNull(o, "key_hex"),
                hexOrNull(o, "master_key_hex"),
                hexOrNull(o, "agent_key_hex"),
                o.has("agent_pid") ? o.get("agent_pid").getAsInt() : -1,
                o.has("agent_id") ? o.get("agent_id").getAsInt() : -1,
                hexOrNull(o, "session_salt_hex"),
                o.has("prefix_index") ? o.get("prefix_index").getAsInt() : -1,
                o.has("epoch") ? o.get("epoch").getAsLong() : -1L,
                hexOrNull(o, "iv_random_hex"),
                o.has("iv_counter") ? o.get("iv_counter").getAsInt() : 0,
                hexOrNull(o, "plaintext_hex"),
                hexOrNull(o, "info_hex"),
                hexOrNull(o, "derived_agent_key_hex"),
                hexOrNull(o, "expected_wire_hex"),
                hexOrNull(o, "expected_okm_hex"),
                hexOrNull(o, "expected_iv_prefix_hex")));
        }
        return out;
    }

    private static byte[] hex(String s) {
        return s.isEmpty() ? new byte[0] : HexFormat.of().parseHex(s);
    }

    private static byte[] hexOrNull(JsonObject o, String key) {
        if (!o.has(key) || o.get(key).isJsonNull()) return null;
        return hex(o.get(key).getAsString());
    }

    public record CrcVector(String id, byte[] input, long expectedCrc) {}

    public record FrameVector(
        String id, String kind, String expectedDecodeError,
        String status, int pid, long timestamp, long nonce, int payload,
        byte[] expectedWire,
        byte[] decodeErrorWire) {}

    public record SecureVector(
        String id, String kind,
        byte[] key, byte[] masterKey, byte[] agentKey,
        int agentPid, int agentId,
        byte[] sessionSalt, int prefixIndex, long epoch,
        byte[] ivRandom, int ivCounter,
        byte[] plaintext, byte[] info,
        byte[] derivedAgentKey,
        byte[] expectedWire, byte[] expectedOkm, byte[] expectedIvPrefix) {}
}
