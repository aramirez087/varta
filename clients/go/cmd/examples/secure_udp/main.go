// Varta agent over ChaCha20-Poly1305 AEAD UDP. Mirror of
// clients/python/examples/secure_udp.py and
// crates/varta-client/examples/secure_udp.rs.
//
// The key is read from --key-file (32 raw bytes); in a real
// deployment supply a Kubernetes secret, HashiCorp Vault entry, or
// similar.
package main

import (
	"flag"
	"log"
	"os"
	"time"

	varta "github.com/aramirez087/Varta/clients/go"
)

func main() {
	host := flag.String("host", "127.0.0.1", "observer host")
	port := flag.Int("port", 9443, "observer secure-UDP port")
	keyFile := flag.String("key-file", "", "path to a 32-byte shared key (raw bytes)")
	flag.Parse()

	if *keyFile == "" {
		log.Fatal("--key-file is required")
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("read key file: %v", err)
	}
	if len(key) != 32 {
		log.Fatalf("key file must contain exactly 32 bytes (got %d)", len(key))
	}

	agent, err := varta.ConnectSecureUDP(*host, *port, key)
	if err != nil {
		log.Fatalf("varta: connect secure-udp %s:%d: %v", *host, *port, err)
	}
	defer agent.Close()

	for {
		outcome := agent.Beat(varta.StatusOK, 0)
		if outcome.IsFailed() {
			log.Printf("varta: beat failed: %v", outcome.Err())
		}
		time.Sleep(500 * time.Millisecond)
	}
}
