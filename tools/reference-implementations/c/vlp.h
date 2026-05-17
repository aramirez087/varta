/* VLP v0.2 — non-normative C99 reference implementation.
 *
 * Authoritative spec: book/src/spec/vlp.md.
 *
 * Covers the 32-byte base frame: encode, decode, and CRC-32C. Secure
 * transport (ChaCha20-Poly1305) is intentionally out of scope for the
 * C reference; the Python/Go/Rust references already cover it without
 * pulling libsodium into this directory.
 */
#ifndef VARTA_VLP_H
#define VARTA_VLP_H

#include <stddef.h>
#include <stdint.h>

#define VARTA_FRAME_BYTES   32u
#define VARTA_MAGIC_0       0x56u  /* 'V' */
#define VARTA_MAGIC_1       0x41u  /* 'A' */
#define VARTA_VERSION       0x02u
#define VARTA_NONCE_TERMINAL 0xFFFFFFFFFFFFFFFFuLL

typedef enum {
    VARTA_STATUS_OK       = 0,
    VARTA_STATUS_DEGRADED = 1,
    VARTA_STATUS_CRITICAL = 2,
    VARTA_STATUS_STALL    = 3   /* observer-synthesized only */
} varta_status_t;

typedef enum {
    VARTA_DECODE_OK = 0,
    VARTA_DECODE_BAD_MAGIC,
    VARTA_DECODE_BAD_VERSION,
    VARTA_DECODE_BAD_CRC,
    VARTA_DECODE_BAD_STATUS,
    VARTA_DECODE_STALL_ON_WIRE,
    VARTA_DECODE_BAD_PID,
    VARTA_DECODE_BAD_TIMESTAMP,
    VARTA_DECODE_BAD_NONCE
} varta_decode_kind_t;

typedef struct {
    varta_status_t status;
    uint32_t       pid;
    uint64_t       timestamp;
    uint64_t       nonce;
    uint32_t       payload;
} varta_frame_t;

/* CRC-32C (Castagnoli). RFC 3720 appendix B compatible.  */
uint32_t varta_crc32c(const uint8_t *data, size_t len);

/* Encode 32 bytes into `out`. `out` MUST point to >=32 writable bytes. */
void varta_encode(varta_status_t status,
                  uint32_t pid,
                  uint64_t timestamp,
                  uint64_t nonce,
                  uint32_t payload,
                  uint8_t out[VARTA_FRAME_BYTES]);

/* Decode 32 bytes. Returns VARTA_DECODE_OK and populates `*frame` on success;
 * otherwise returns the first failed validation step (see vlp.md §5). */
varta_decode_kind_t varta_decode(const uint8_t buf[VARTA_FRAME_BYTES],
                                 varta_frame_t *frame);

/* Match the kind enum to the spec-defined error name (BadMagic, BadVersion,
 * BadCrc, BadStatus, StallOnWire, BadPid, BadTimestamp, BadNonce). */
const char *varta_decode_kind_name(varta_decode_kind_t kind);

#endif /* VARTA_VLP_H */
