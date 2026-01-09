//go:build !windows

package main

import (
	"flag"
	"log"

	"github.com/Pos1t1veGuy/MoonVPN/core/linux"
)

func main() {
	host := flag.String("host", "127.0.0.1", "application host")
	port := flag.Int("port", 8080, "application port")
	flag.Parse()

	srv := linux.NewLinuxServer(*host, *port, "10.0.0.1/24")
	log.Printf("Starting server on %s:%d", *host, *port)
	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
