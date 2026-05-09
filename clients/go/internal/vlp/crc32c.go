// Package vlp implements the VLP v0.2 base wire frame for the Varta Go
// client. The normative specification lives at book/src/spec/vlp.md.
//
// Standard library only; safe to import from the panic subpackage.
package vlp

// CRC-32C (Castagnoli) — RFC 3720 appendix B. Reflected polynomial,
// table-driven byte-at-a-time. Matches the canonical Rust
// implementation at crates/varta-vlp/src/crc32c.rs and the Python
// implementation at clients/python/src/varta/_vlp.py.
const crc32cReflectedPoly = uint32(0x82F63B78)

var crc32cTable = func() [256]uint32 {
	var t [256]uint32
	for i := uint32(0); i < 256; i++ {
		c := i
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = (c >> 1) ^ crc32cReflectedPoly
			} else {
				c = c >> 1
			}
		}
		t[i] = c
	}
	return t
}()

// CRC32C returns the Castagnoli CRC-32C of data. Init 0xFFFFFFFF,
// refin/refout, output XOR 0xFFFFFFFF.
func CRC32C(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = crc32cTable[(crc^uint32(b))&0xff] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}
