// Public surface of `@varta/client`. See `README.md` for the parity
// table against the Rust, Python, and Go clients.

export { Varta } from "./client.js";
export {
  Status,
  NONCE_TERMINAL,
  FRAME_BYTES,
  MAGIC,
  VERSION,
  DecodeError,
  decode,
  decodeFrame,
  encode,
  encodeInto,
  crc32c,
  type Frame,
  type StatusLike,
  type DecodeErrorKind,
} from "./vlp.js";
export {
  BeatOutcomes,
  BeatError,
  DropReason,
  classifySendError,
  isSent,
  isDropped,
  isFailed,
  type BeatOutcome,
} from "./outcome.js";
export {
  UdpTransport,
  SecureUdpTransport,
  UdsTransport,
  UdsUnavailableError,
  type BeatTransport,
} from "./transport.js";
export * as panic from "./panic.js";
