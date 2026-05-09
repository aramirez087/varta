// Beat loop that packs queue depth and last error code into the
// 32-bit payload field. Mirror of clients/python/examples/with_payload.py
// and crates/varta-client/examples/with_payload.rs.
package main

import (
	"flag"
	"log"
	"math/rand"
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
		// Pack: high 16 bits = queue depth, low 16 bits = error code.
		queueDepth := uint16(rand.Intn(1024))
		errorCode := uint16(rand.Intn(256))
		payload := (uint32(queueDepth) << 16) | uint32(errorCode)

		status := varta.StatusOK
		if errorCode > 200 {
			status = varta.StatusDegraded
		}

		agent.Beat(status, payload)
		time.Sleep(500 * time.Millisecond)
	}
}
