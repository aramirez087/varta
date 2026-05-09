// Public re-exports — the surface that user code sees as
// `varta.Foo`. The wire codec lives in internal/vlp; the secure
// transport in internal/transport.
package varta

import "github.com/aramirez087/Varta/clients/go/internal/vlp"

// Status is the beat status; matches the 1-byte wire value at offset 3.
// Re-export of the internal type so user code does not need to import
// internal packages.
type Status = vlp.Status

// Status constants — wire-side bytes match book/src/spec/vlp.md §4.
const (
	StatusOK       = vlp.StatusOk
	StatusDegraded = vlp.StatusDegraded
	StatusCritical = vlp.StatusCritical
)

// NonceTerminal is the reserved sentinel nonce. Only valid paired with
// StatusCritical; identifies a panic-emitted terminal frame. User code
// should not emit this from Beat — the panic subpackage owns it.
const NonceTerminal = vlp.NonceTerminal

// Frame is the decoded view of a 32-byte wire frame. Re-exported for
// callers that want to decode beats themselves.
type Frame = vlp.Frame

// DecodeError is the wire-validation failure type. Re-exported so
// callers can type-assert with errors.As.
type DecodeError = vlp.DecodeError

// FrameBytes is the fixed wire length of a base VLP frame.
const FrameBytes = vlp.FrameBytes

// DecodeFrame validates a 32-byte buffer and returns the recovered
// Frame. Exposed for tooling that consumes raw beats off the wire.
func DecodeFrame(buf []byte) (Frame, error) { return vlp.Decode(buf) }
