/* verify_vectors.c — exercise the conformance suite from vectors.h. */
#include <stdio.h>
#include <string.h>

#include "vlp.h"
#include "vectors.h"

static int failures = 0;

static void hex_print(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; ++i) printf("%02x", buf[i]);
}

static int memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    return memcmp(a, b, n) == 0;
}

int main(void) {
    /* ----- CRC ----- */
    for (size_t i = 0; i < crc_vectors_count; ++i) {
        const crc_vec_t *v = &crc_vectors[i];
        uint32_t got = varta_crc32c(v->input, v->input_len);
        if (got != v->expected_crc) {
            ++failures;
            fprintf(stderr, "FAIL crc/%s: got %08x, want %08x\n",
                    v->id, got, v->expected_crc);
        }
    }
    printf("crc32c_vectors:        %zu OK\n", crc_vectors_count);

    /* ----- Frames ----- */
    size_t roundtrip = 0, errs = 0;
    for (size_t i = 0; i < frame_vectors_count; ++i) {
        const frame_vec_t *v = &frame_vectors[i];
        if (v->status >= 0) {
            /* encode_decode_roundtrip */
            uint8_t out[VARTA_FRAME_BYTES];
            varta_encode((varta_status_t)v->status, v->pid, v->timestamp,
                         v->nonce, v->payload, out);
            if (!memeq(out, v->wire, VARTA_FRAME_BYTES)) {
                ++failures;
                fprintf(stderr, "FAIL frame/%s: encode mismatch\n  got  ", v->id);
                hex_print(out, VARTA_FRAME_BYTES);
                fprintf(stderr, "\n  want ");
                hex_print(v->wire, VARTA_FRAME_BYTES);
                fprintf(stderr, "\n");
                continue;
            }
            varta_frame_t f;
            varta_decode_kind_t k = varta_decode(v->wire, &f);
            if (k != VARTA_DECODE_OK) {
                ++failures;
                fprintf(stderr, "FAIL frame/%s: golden does not decode (%s)\n",
                        v->id, varta_decode_kind_name(k));
                continue;
            }
            if (f.status != (varta_status_t)v->status || f.pid != v->pid
                || f.timestamp != v->timestamp || f.nonce != v->nonce
                || f.payload != v->payload) {
                ++failures;
                fprintf(stderr, "FAIL frame/%s: round-trip field mismatch\n", v->id);
                continue;
            }
            ++roundtrip;
        } else {
            /* decode_error */
            varta_frame_t f;
            varta_decode_kind_t k = varta_decode(v->wire, &f);
            const char *got = varta_decode_kind_name(k);
            if (k == VARTA_DECODE_OK || strcmp(got, v->expected_decode_error) != 0) {
                ++failures;
                fprintf(stderr, "FAIL frame/%s: expected %s, got %s\n",
                        v->id, v->expected_decode_error, got);
                continue;
            }
            ++errs;
        }
    }
    printf("frame_vectors:         %zu round-trips, %zu error vectors OK\n",
           roundtrip, errs);

    /* secure_frame_vectors are covered by Python/Go/Rust references; the
     * C reference is base-spec only. See README.md. */
    puts("secure_frame_vectors:  (skipped — see README.md)");

    if (failures > 0) {
        fprintf(stderr, "\nFAILED: %d vector(s)\n", failures);
        return 1;
    }
    puts("");
    puts("ALL VECTORS PASSED (base spec)");
    return 0;
}
