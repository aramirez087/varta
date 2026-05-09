// Minimal Varta beat loop — connect once, emit Status=OK every 500 ms.
// Mirror of clients/python/examples/basic_uds.py and
// crates/varta-client/examples/basic.rs.
package main

import (
	"flag"
	"log"
	"time"

	varta "github.com/aramirez087/Varta/clients/go"
)

func main() {
	path := flag.String("socket", "/run/varta/varta.sock", "observer UDS path")
	flag.Parse()

	agent, err := varta.Connect(*path)
	if err != nil {
		log.Fatalf("varta: connect %s: %v", *path, err)
	}
	defer agent.Close()

	for {
		outcome := agent.Beat(varta.StatusOK, 0)
		if outcome.IsDropped() {
			// Observer absent, kernel queue full, peer gone, or disk full.
			// Treat as a no-op; the next beat will retry.
		} else if outcome.IsFailed() {
			log.Printf("varta: beat failed: %v", outcome.Err())
		}
		time.Sleep(500 * time.Millisecond)
	}
}
