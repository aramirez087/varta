// Package varta is the production Go client for the Varta health
// protocol. It emits 32-byte VLP v0.2 heartbeat frames to a varta-watch
// observer over a Unix Domain Socket, plaintext UDP, or
// ChaCha20-Poly1305-encrypted UDP.
//
// The agent is non-blocking: a kernel-queue-full send surfaces as
// BeatOutcome.Dropped(KernelQueueFull), never a block. Fork is
// detected per beat by comparing the current PID to the snapshot taken
// at Connect; on mismatch the transport is rebuilt (and, for
// secure-UDP, the AEAD session salt is re-read from crypto/rand)
// before the frame is encoded.
//
// Quickstart:
//
//	agent, err := varta.Connect("/run/varta/varta.sock")
//	if err != nil { log.Fatal(err) }
//	defer agent.Close()
//	for {
//	    agent.Beat(varta.StatusOK, 0)
//	    time.Sleep(500 * time.Millisecond)
//	}
//
// Wire format and KDF/AEAD constructions are normative — see
// book/src/spec/vlp.md and book/src/spec/vlp-secure.md in the Varta
// repository. The same tools/vlp-test-vectors.json fixture verifies
// this client against the Rust and Python implementations on every CI
// run.
package varta
