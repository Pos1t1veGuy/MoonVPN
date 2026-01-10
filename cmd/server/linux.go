//go:build !windows

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Pos1t1veGuy/MoonVPN/core"
)

func main() {
	validLogLevels := map[string]struct{}{
		"debug": {},
		"info":  {},
		"warn":  {},
		"error": {},
	}

	cidr := flag.String("cidr", "10.0.0.1/24", "application net interface CIDR")
	host := flag.String("host", "0.0.0.0", "application host")
	logLevel := flag.String("logLevel", "info", "application log level (debug, info, warn, error)")
	port := flag.Int("port", 5555, "application port")
	flag.Parse()

	if _, ok := validLogLevels[*logLevel]; !ok {
		fmt.Fprintf(os.Stderr, "invalid logLevel: %q\n", *logLevel)
		os.Exit(1)
	}

	core.InitLogger(*logLevel)
	srv := core.NewLinuxServer(*host, *port, *cidr)
	srv.Start()
}
