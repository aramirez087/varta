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
//! See `docs/architecture/vlp-frame.md` for the byte map and design notes.

/// Magic prefix on every VLP frame. ASCII `"VA"`, intentionally readable in
/// hex dumps so a stray byte stream is easy to identify.
pub const MAGIC: [u8; 2] = [0x56, 0x41];

/// Current Varta Lifeline Protocol version. v0.1.0 ships only `0x01`; any
/// future on-wire change bumps this byte and adds a [`DecodeError::BadVersion`]
/// path.
pub const VERSION: u8 = 0x01;

/// Sentinel nonce value reserved for terminal panic frames.
///
/// Regular beats from `varta_client::Varta::beat` cap their nonce at
/// `NONCE_TERMINAL - 1` so that observers can unambiguously identify a
/// panic-fired critical frame by its nonce alone.
pub const NONCE_TERMINAL: u64 = u64::MAX;

/// Health status reported by an agent in a single VLP frame.
///
/// The discriminants are explicit because they form part of the on-wire
/// contract: agents serialise `Status as u8` and observers reconstruct via
/// [`Status::try_from_u8`].
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
    /// mark a final critical frame. Regular beats cap at `NONCE_TERMINAL - 1`.
    pub nonce: u64,
    /// Free-form 8-byte payload — application-defined health context (queue
    /// depth, error code, etc.). Carried opaquely by the protocol.
    pub payload: u64,
}

const _: () = assert!(core::mem::size_of::<Frame>() == 32);
const _: () = assert!(core::mem::align_of::<Frame>() == 8);
const _: () = assert!(core::mem::offset_of!(Frame, magic) == 0);
const _: () = assert!(core::mem::offset_of!(Frame, version) == 2);
const _: () = assert!(core::mem::offset_of!(Frame, status) == 3);
const _: () = assert!(core::mem::offset_of!(Frame, pid) == 4);
const _: () = assert!(core::mem::offset_of!(Frame, timestamp) == 8);
const _: () = assert!(core::mem::offset_of!(Frame, nonce) == 16);
const _: () = assert!(core::mem::offset_of!(Frame, payload) == 24);

impl Frame {
    /// Construct a new frame with the canonical [`MAGIC`] prefix and
    /// [`VERSION`] byte already populated. All other fields are
    /// caller-supplied.
    pub const fn new(status: Status, pid: u32, timestamp: u64, nonce: u64, payload: u64) -> Frame {
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
    pub fn encode(&self, out: &mut [u8; 32]) {
        out[0..2].copy_from_slice(&self.magic);
        out[2] = self.version;
        out[3] = self.status as u8;
        out[4..8].copy_from_slice(&self.pid.to_le_bytes());
        out[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        out[16..24].copy_from_slice(&self.nonce.to_le_bytes());
        out[24..32].copy_from_slice(&self.payload.to_le_bytes());
    }

    /// Decode a 32-byte buffer back into a [`Frame`], validating magic,
    /// version, and status in that order. Returns [`DecodeError`] on the
    /// first failed check; the integer fields are not interpreted further.
    pub fn decode(bytes: &[u8; 32]) -> Result<Frame, DecodeError> {
        let magic = [bytes[0], bytes[1]];
        if magic != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let version = bytes[2];
        if version != VERSION {
            return Err(DecodeError::BadVersion);
        }
        let status = Status::try_from_u8(bytes[3])?;

        let pid = u32::from_le_bytes(bytes[4..8].try_into().unwrap_or([0, 0, 0, 0]));
        let timestamp = u64::from_le_bytes(bytes[8..16].try_into().unwrap_or([0; 8]));
        let nonce = u64::from_le_bytes(bytes[16..24].try_into().unwrap_or([0; 8]));
        let payload = u64::from_le_bytes(bytes[24..32].try_into().unwrap_or([0; 8]));

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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// First two bytes did not equal [`MAGIC`].
    BadMagic,
    /// Version byte did not equal [`VERSION`].
    BadVersion,
    /// Status byte did not match any known [`Status`] variant. The inner
    /// value is the offending byte, surfaced for observer-side diagnostics.
    BadStatus(u8),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::BadMagic => f.write_str("varta-vlp: bad magic prefix"),
            DecodeError::BadVersion => f.write_str("varta-vlp: bad version byte"),
            DecodeError::BadStatus(byte) => {
                write!(f, "varta-vlp: bad status byte {byte:#04x}")
            }
        }
    }
}

impl core::error::Error for DecodeError {}
