/* VLP v0.2 base-frame reference. See vlp.h. */
#include "vlp.h"

#include <string.h>

/* ----------------------------- CRC-32C --------------------------------- */

#define VARTA_CRC_POLY_REFLECTED 0x82F63B78u

static uint32_t crc_table[256];
static int crc_table_built;

static void build_crc_table(void)
{
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int j = 0; j < 8; ++j) {
            c = (c & 1u) ? (c >> 1) ^ VARTA_CRC_POLY_REFLECTED : c >> 1;
        }
        crc_table[i] = c;
    }
    crc_table_built = 1;
}

uint32_t varta_crc32c(const uint8_t *data, size_t len)
{
    if (!crc_table_built) build_crc_table();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc = crc_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* --------------------------- LE byte writes ---------------------------- */

static void put_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v        & 0xFFu);
    p[1] = (uint8_t)((v >> 8)  & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}
static void put_u64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
}
static uint32_t get_u32_le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

/* --------------------------- Encode / Decode --------------------------- */

void varta_encode(varta_status_t status,
                  uint32_t pid,
                  uint64_t timestamp,
                  uint64_t nonce,
                  uint32_t payload,
                  uint8_t out[VARTA_FRAME_BYTES])
{
    out[0] = VARTA_MAGIC_0;
    out[1] = VARTA_MAGIC_1;
    out[2] = VARTA_VERSION;
    out[3] = (uint8_t)status;
    put_u32_le(&out[4],  pid);
    put_u64_le(&out[8],  timestamp);
    put_u64_le(&out[16], nonce);
    put_u32_le(&out[24], payload);
    uint32_t crc = varta_crc32c(out, 28);
    put_u32_le(&out[28], crc);
}

varta_decode_kind_t varta_decode(const uint8_t buf[VARTA_FRAME_BYTES],
                                 varta_frame_t *frame)
{
    if (buf[0] != VARTA_MAGIC_0 || buf[1] != VARTA_MAGIC_1)
        return VARTA_DECODE_BAD_MAGIC;
    if (buf[2] != VARTA_VERSION)
        return VARTA_DECODE_BAD_VERSION;

    uint32_t stored = get_u32_le(&buf[28]);
    uint32_t computed = varta_crc32c(buf, 28);
    if (stored != computed)
        return VARTA_DECODE_BAD_CRC;

    uint8_t status_byte = buf[3];
    if (status_byte > 3)
        return VARTA_DECODE_BAD_STATUS;
    if (status_byte == VARTA_STATUS_STALL)
        return VARTA_DECODE_STALL_ON_WIRE;

    uint32_t pid       = get_u32_le(&buf[4]);
    uint64_t timestamp = get_u64_le(&buf[8]);
    uint64_t nonce     = get_u64_le(&buf[16]);
    uint32_t payload   = get_u32_le(&buf[24]);

    if (pid == 0u || pid == 1u)
        return VARTA_DECODE_BAD_PID;
    if (timestamp == 0xFFFFFFFFFFFFFFFFuLL)
        return VARTA_DECODE_BAD_TIMESTAMP;
    if (nonce == VARTA_NONCE_TERMINAL && status_byte != (uint8_t)VARTA_STATUS_CRITICAL)
        return VARTA_DECODE_BAD_NONCE;

    if (frame) {
        frame->status    = (varta_status_t)status_byte;
        frame->pid       = pid;
        frame->timestamp = timestamp;
        frame->nonce     = nonce;
        frame->payload   = payload;
    }
    return VARTA_DECODE_OK;
}

const char *varta_decode_kind_name(varta_decode_kind_t kind)
{
    switch (kind) {
    case VARTA_DECODE_OK:            return "Ok";
    case VARTA_DECODE_BAD_MAGIC:     return "BadMagic";
    case VARTA_DECODE_BAD_VERSION:   return "BadVersion";
    case VARTA_DECODE_BAD_CRC:       return "BadCrc";
    case VARTA_DECODE_BAD_STATUS:    return "BadStatus";
    case VARTA_DECODE_STALL_ON_WIRE: return "StallOnWire";
    case VARTA_DECODE_BAD_PID:       return "BadPid";
    case VARTA_DECODE_BAD_TIMESTAMP: return "BadTimestamp";
    case VARTA_DECODE_BAD_NONCE:     return "BadNonce";
    }
    return "Unknown";
}
