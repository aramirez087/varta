#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs, unsafe_op_in_unsafe_fn, rust_2018_idioms)]
#![forbid(clippy::dbg_macro, clippy::print_stdout)]

//! Varta Lifeline Protocol — 32-byte fixed-layout health frame.
//!
//! This crate is the protocol root for Varta v0.1.0. It defines the on-wire
//! [`Frame`] representation that agents emit and observers decode, the
//! [`Status`] enum that classifies an agent's last reported health, and the
//! [`DecodeError`] returned when validation fails. Every helper operates on
//! fixed-size byte arrays so the steady-state path on either side of the
//! socket is heap-clean.
//!
//! The crate compiles as `#![no_std]` by default and pulls in zero allocator
//! usage; the optional `std` feature enables `Key::from_file` and related
//! `std::path::Path`-typed conveniences.
//!
//! See `book/src/architecture/vlp-frame.md` for the byte map and design notes.

// Unit tests live inside the lib crate and use `format!` / `assert_eq!` against
// dynamic strings; pull `std` in for the test harness only. This does not
// affect the production library's `#![no_std]` posture in any build mode.
#[cfg(test)]
extern crate std;

#[cfg(feature = "crypto")]
pub mod crypto;

pub mod crc32c;
pub mod util;
pub use util::{ct_eq, decode_hex_32, HexDecodeError};

// Symbolic-verification harnesses live in their own module gated
// `#[cfg(kani)]` so they compile only under `cargo kani`.  The Kani crate
// is injected by the verifier and never appears in [`Cargo.toml`]; the
// zero-registry-dependency invariant for varta-vlp is preserved.
//
// See `book/src/architecture/verification.md`.
#[cfg(kani)]
pub mod proofs;

/// Magic prefix on every VLP frame. ASCII `"VA"`, intentionally readable in
/// hex dumps so a stray byte stream is easy to identify.
pub const MAGIC: [u8; 2] = [0x56, 0x41];

/// Current Varta Lifeline Protocol version. v0.2 introduces the CRC-32C
/// integrity trailer at bytes 28..32 and shrinks `payload` from `u64` to
/// `u32` to fit it. v0.1 frames decode as [`DecodeError::BadVersion`].
pub const VERSION: u8 = 0x02;

// Compile-time guard: VLP frame layout is little-endian by specification
// (see book/src/architecture/vlp-frame.md). Building on a big-endian host would
// silently produce broken frames.
#[cfg(not(target_endian = "little"))]
compile_error!(
    "VLP frame protocol requires little-endian host (see book/src/architecture/vlp-frame.md)"
);

/// Sentinel nonce value reserved for terminal panic frames.
///
/// Emitted only by `varta_client::panic::install*` panic hooks, paired with
/// [`Status::Critical`]. Regular beats from `varta_client::Varta::beat`
/// increment monotonically from 1 and wrap to 0 on exhaustion (the wrap
/// boundary in the client is `NONCE_TERMINAL - 1 → 0`), so the regular-beat
/// nonce stream structurally never collides with this sentinel.
///
/// [`Frame::decode`] enforces `NONCE_TERMINAL ⇒ Status::Critical`
/// ([`DecodeError::BadNonce`] otherwise). The converse is *not* enforced —
/// operators may emit `Status::Critical` for non-panic alerts at any nonce.
/// Downstream consumers that need to distinguish "panic terminal" from
/// "operational critical" must inspect both `status` *and* `nonce`.
///
/// See `book/src/architecture/vlp-frame.md` ("Nonce semantics") for the
/// full protocol-level rationale.
pub const NONCE_TERMINAL: u64 = u64::MAX;

/// Health status reported by an agent in a single VLP frame.
///
/// The discriminants are explicit because they form part of the on-wire
/// contract: agents serialise `Status as u8` and observers reconstruct via
/// [`Status::try_from_u8`].
///
/// This enum is exhaustive. Adding a variant is a workspace-wide compile-error
/// change. The wire format (version-pinned by [`VERSION`]) guarantees that no
/// in-memory `Status` value exists outside this list; unknown bytes are rejected
/// by [`Status::try_from_u8`] as [`DecodeError::BadStatus`].
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Status {
    /// The agent is healthy and making progress.
    Ok = 0,
    /// The agent is making progress but reporting elevated trouble (e.g.
    /// retrying, throttled).
    Degraded = 1,
    /// The agent is about to die. Emitted by the panic hook in
    /// `varta-client` immediately before unwinding.
    Critical = 2,
    /// The agent appears stuck. Emitted by `varta-watch` when no beat has
    /// arrived within the configured threshold.
    Stall = 3,
}

impl Status {
    /// Decode a status byte from the wire format. Returns
    /// [`DecodeError::BadStatus`] carrying the offending byte if the value is
    /// not a known variant.
    pub fn try_from_u8(byte: u8) -> Result<Self, DecodeError> {
        match byte {
            0 => Ok(Status::Ok),
            1 => Ok(Status::Degraded),
            2 => Ok(Status::Critical),
            3 => Ok(Status::Stall),
            other => Err(DecodeError::BadStatus(other)),
        }
    }
}

/// On-wire health frame — exactly 32 bytes, 8-byte aligned, little-endian
/// integer fields. The struct is `repr(C)` so its layout is ABI-stable across
/// compilations and trivially verifiable by inspection.
///
/// Construct frames directly via the public fields, then call
/// [`Frame::encode`] to write to a socket buffer or [`Frame::decode`] to read
/// one. There is no `Default`; agents always supply a real `pid`, `nonce` and
/// timestamp.
#[non_exhaustive]
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame {
    /// Magic prefix, always equal to [`MAGIC`].
    pub magic: [u8; 2],
    /// Protocol version, always equal to [`VERSION`] on emit.
    pub version: u8,
    /// Health status reported by the agent. Encoded on the wire as a
    /// single byte at offset 3 ([`Status`] discriminants are `#[repr(u8)]`).
    pub status: Status,
    /// OS process id of the emitting agent.
    pub pid: u32,
    /// Monotonic timestamp chosen by the emitter (typically nanoseconds since
    /// some agent-local epoch). Observers do not interpret it; they only
    /// compare consecutive timestamps for the same pid.
    pub timestamp: u64,
    /// Strictly increasing counter, starting at 1 on the first beat after
    /// `Varta::connect`. The panic hook pins this to [`NONCE_TERMINAL`] to
    /// mark a final critical frame.
    ///
    /// Regular beats wrap at `NONCE_TERMINAL - 1 → 0` on exhaustion, so the
    /// regular-beat nonce stream **structurally never collides** with
    /// [`NONCE_TERMINAL`]. A wire frame with `nonce == NONCE_TERMINAL` is, by
    /// construction, a panic frame (and [`Frame::decode`] enforces it must
    /// also carry [`Status::Critical`]).
    pub nonce: u64,
    /// Free-form 4-byte payload — application-defined health context (queue
    /// depth, error code, etc.). Carried opaquely by the protocol. Shrunk
    /// from `u64` to `u32` in VLP v0.2 to fit the CRC-32C trailer in 32
    /// bytes; the on-wire CRC occupies bytes 28..32 and is not surfaced as
    /// a struct field — see [`Frame::encode`] / [`Frame::decode`].
    pub payload: u32,
}

const _: () = assert!(core::mem::size_of::<Frame>() == 32);
const _: () = assert!(core::mem::align_of::<Frame>() == 8);

impl Frame {
    /// Construct a new frame with the canonical [`MAGIC`] prefix and
    /// [`VERSION`] byte already populated. All other fields are
    /// caller-supplied.
    pub const fn new(status: Status, pid: u32, timestamp: u64, nonce: u64, payload: u32) -> Frame {
        Frame {
            magic: MAGIC,
            version: VERSION,
            status,
            pid,
            timestamp,
            nonce,
            payload,
        }
    }

    /// Serialise this frame into a 32-byte buffer in canonical
    /// little-endian layout. The output buffer is overwritten in place; this
    /// method allocates nothing.
    ///
    /// Bytes 28..32 are stamped with a CRC-32C computed over bytes 0..28 —
    /// see [`crate::crc32c`]. The CRC is a wire-format artifact, not a
    /// struct field; callers must never mutate the buffer between `encode`
    /// and the on-wire write or the receiver will reject the frame as
    /// [`DecodeError::BadCrc`].
    pub fn encode(&self, out: &mut [u8; 32]) {
        out[0..2].copy_from_slice(&self.magic);
        out[2] = self.version;
        out[3] = self.status as u8;
        out[4..8].copy_from_slice(&self.pid.to_le_bytes());
        out[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        out[16..24].copy_from_slice(&self.nonce.to_le_bytes());
        out[24..28].copy_from_slice(&self.payload.to_le_bytes());
        let crc = crc32c::compute(&out[0..28]);
        out[28..32].copy_from_slice(&crc.to_le_bytes());
    }

    /// Decode a 32-byte buffer back into a [`Frame`], validating magic,
    /// version, CRC, status, and field ranges in that order. Returns
    /// [`DecodeError`] on the first failed check.
    ///
    /// Order rationale: `magic` + `version` come first so random bytes
    /// from a wrong-protocol sender surface as
    /// [`DecodeError::BadMagic`] / [`DecodeError::BadVersion`] (the
    /// "this isn't even VLP" diagnostic). The CRC then gates every
    /// field-range check — a single-bit-flipped status byte must surface
    /// as [`DecodeError::BadCrc`], not as a valid frame with the wrong
    /// meaning.
    ///
    /// Field-range rules enforced after the CRC passes:
    /// * `status == Status::Stall` is rejected — `Stall` is observer-synthesized
    ///   by `varta-watch` when a pid goes silent past its threshold; no
    ///   legitimate agent emits it on the wire. Accepting a spoofed `Stall`
    ///   frame would let a hostile sender pollute observer telemetry from
    ///   any pid.
    /// * `pid ∈ {0, 1}` is rejected — pid 0 is the kernel/scheduler and
    ///   pid 1 is init/systemd; no legitimate agent runs at either, and
    ///   accepting them lets a hostile sender spoof "init has stalled" to
    ///   the recovery path.
    /// * `timestamp == u64::MAX` is rejected — `varta_client::Varta::beat`
    ///   saturates at this value with `.min(u64::MAX as u128) as u64`, and
    ///   reaching it through real elapsed time (~584 years) is impossible.
    ///   The sentinel is reserved.
    ///
    ///   *Asymmetry note*: a hypothetical agent whose monotonic clock
    ///   saturates still observes `BeatOutcome::Sent` from `send(2)` (the
    ///   kernel sees a well-formed 32-byte datagram), while the observer
    ///   drops the frame as `DecodeError::BadTimestamp`. The divergence is
    ///   physically unreachable on a single `Varta::connect` handle and is
    ///   documented for completeness only.
    /// * `nonce == NONCE_TERMINAL` is allowed only when paired with
    ///   `Status::Critical`; the sentinel is the panic-hook's terminal
    ///   marker and is never emitted on the regular beat path.
    pub fn decode(bytes: &[u8; 32]) -> Result<Frame, DecodeError> {
        let magic = [bytes[0], bytes[1]];
        if magic != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let version = bytes[2];
        if version != VERSION {
            return Err(DecodeError::BadVersion);
        }

        // CRC trailer at bytes 28..32 covers bytes 0..28. Verified after
        // magic/version (so wrong-protocol bytes surface as BadMagic, not
        // BadCrc) and before any field-range check (so corruption cannot
        // produce a "well-formed" frame with the wrong meaning).
        let stored_crc = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        let computed_crc = crc32c::compute(&bytes[0..28]);
        if stored_crc != computed_crc {
            return Err(DecodeError::BadCrc {
                expected: computed_crc,
                actual: stored_crc,
            });
        }

        let status = Status::try_from_u8(bytes[3])?;
        if status == Status::Stall {
            return Err(DecodeError::StallOnWire);
        }

        // Each integer field is decoded via explicit array indexing — the
        // compiler statically proves every index is in-bounds against the
        // `&[u8; 32]` reference, so there are no runtime panics.
        let pid = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let timestamp = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let nonce = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let payload = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);

        if pid == 0 || pid == 1 {
            return Err(DecodeError::BadPid(pid));
        }
        if timestamp == u64::MAX {
            return Err(DecodeError::BadTimestamp(timestamp));
        }
        if nonce == NONCE_TERMINAL && status != Status::Critical {
            return Err(DecodeError::BadNonce { nonce, status });
        }

        Ok(Frame {
            magic,
            version,
            status,
            pid,
            timestamp,
            nonce,
            payload,
        })
    }
}

/// Error returned by [`Frame::decode`] and [`Status::try_from_u8`].
///
/// The variants form an exhaustive list of validation failures the protocol
/// can detect statically; everything else (timestamp drift, nonce regression)
/// is policy enforced higher in the stack.
///
/// This enum is exhaustive. Adding a variant is a workspace-wide compile-error
/// change that requires updating every match site explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// First two bytes did not equal [`MAGIC`].
    BadMagic,
    /// Version byte did not equal [`VERSION`].
    BadVersion,
    /// CRC-32C trailer at bytes 28..32 did not match the value computed
    /// over bytes 0..28. Indicates wire corruption (cosmic ray / NIC
    /// firmware / non-ECC RAM bit flip) on the UDS transport, or
    /// in-process memory corruption between
    /// [`crate::crypto::open`](crypto::open) and `Frame::decode` on the
    /// secure-UDP transport. AEAD tag failures stay in the transport
    /// layer (`crypto::AuthError`) and never surface as `BadCrc`.
    BadCrc {
        /// CRC-32C recomputed over bytes 0..28 of the received frame.
        expected: u32,
        /// CRC-32C value carried in bytes 28..32 of the received frame.
        actual: u32,
    },
    /// Status byte did not match any known [`Status`] variant. The inner
    /// value is the offending byte, surfaced for observer-side diagnostics.
    BadStatus(u8),
    /// Observer-only status `Status::Stall` observed on the wire. `Stall`
    /// is synthesized by `varta-watch` when a pid goes silent past its
    /// threshold; agents emit only `Ok`, `Degraded`, or `Critical`. A
    /// spoofed `Stall` frame would inject false liveness telemetry from
    /// any pid, so the decoder rejects it at the single chokepoint.
    StallOnWire,
    /// Reserved pid: `0` (kernel/scheduler) or `1` (init/systemd). No
    /// legitimate agent runs at either pid; rejecting closes the "spoof
    /// init has stalled" recovery-trigger attack on UDP listeners.
    BadPid(u32),
    /// Reserved timestamp sentinel `u64::MAX` — the saturation value from
    /// `varta_client::Varta::beat`'s `.min(u64::MAX as u128) as u64`.
    /// Reaching it through real elapsed nanoseconds is not physically
    /// possible.
    BadTimestamp(u64),
    /// Protocol invariant violation: `nonce == NONCE_TERMINAL` is reserved
    /// for the panic hook's terminal frame and MUST be paired with
    /// [`Status::Critical`]. Carries the violating `status` for diagnostics.
    BadNonce {
        /// The terminal-sentinel nonce value observed on the wire.
        nonce: u64,
        /// The status byte that was paired with the sentinel nonce.
        status: Status,
    },
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::BadMagic => f.write_str("varta-vlp: bad magic prefix"),
            DecodeError::BadVersion => f.write_str("varta-vlp: bad version byte"),
            DecodeError::BadCrc { expected, actual } => {
                write!(
                    f,
                    "varta-vlp: bad CRC-32C trailer (expected {expected:#010x}, actual {actual:#010x})"
                )
            }
            DecodeError::BadStatus(byte) => {
                write!(f, "varta-vlp: bad status byte {byte:#04x}")
            }
            DecodeError::StallOnWire => {
                f.write_str("varta-vlp: Status::Stall is observer-only and forbidden on the wire")
            }
            DecodeError::BadPid(pid) => {
                write!(f, "varta-vlp: reserved pid {pid}")
            }
            DecodeError::BadTimestamp(ts) => {
                write!(f, "varta-vlp: reserved timestamp sentinel {ts:#x}")
            }
            DecodeError::BadNonce { nonce, status } => {
                write!(
                    f,
                    "varta-vlp: terminal nonce {nonce:#x} requires Status::Critical, got {status:?}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

#[cfg(test)]
mod layout_tests {
    use super::{Frame, Status};

    #[test]
    fn frame_field_offsets_match_wire_layout() {
        let frame = Frame::new(Status::Ok, 2, 3, 4, 5);
        let base = core::ptr::addr_of!(frame) as usize;

        assert_eq!(core::ptr::addr_of!(frame.magic) as usize - base, 0);
        assert_eq!(core::ptr::addr_of!(frame.version) as usize - base, 2);
        assert_eq!(core::ptr::addr_of!(frame.status) as usize - base, 3);
        assert_eq!(core::ptr::addr_of!(frame.pid) as usize - base, 4);
        assert_eq!(core::ptr::addr_of!(frame.timestamp) as usize - base, 8);
        assert_eq!(core::ptr::addr_of!(frame.nonce) as usize - base, 16);
        assert_eq!(core::ptr::addr_of!(frame.payload) as usize - base, 24);
    }
}
