// Demonstrates the panic subpackage: a terminating-signal handler
// emits a Status=Critical + Nonce=NonceTerminal frame to the observer
// before the process exits, and Run wraps the main loop so a Go panic
// produces the same terminal beat.
//
// Mirror of clients/python/examples/with_panic_handler.py and
// crates/varta-client/examples/with_panic_handler.rs.
package main

import (
	"flag"
	"log"
	"time"

	varta "github.com/aramirez087/Varta/clients/go"
	vpanic "github.com/aramirez087/Varta/clients/go/panic"
)

func main() {
	path := flag.String("socket", "/run/varta/varta.sock", "observer UDS path")
	crash := flag.Bool("crash", false, "intentionally panic after 3 beats to demonstrate Run")
	flag.Parse()

	if err := vpanic.InstallSignalHandlerUDS(*path); err != nil {
		log.Fatalf("varta: install signal handler: %v", err)
	}

	agent, err := varta.Connect(*path)
	if err != nil {
		log.Fatalf("varta: connect %s: %v", *path, err)
	}
	defer agent.Close()

	vpanic.Run(func() {
		for i := 0; i < 10; i++ {
			agent.Beat(varta.StatusOK, uint32(i))
			time.Sleep(500 * time.Millisecond)
			if *crash && i == 2 {
				panic("intentional panic to demonstrate vpanic.Run")
			}
		}
	})
}
