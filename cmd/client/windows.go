//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Pos1t1veGuy/MoonVPN/core"
	"github.com/rs/zerolog/log"
)

func main() {
	validLogLevels := map[string]struct{}{
		"debug": {},
		"info":  {},
		"warn":  {},
		"error": {},
	}

	appHost := flag.String("appHost", "127.0.0.1", "application host")
	appPort := flag.Int("appPort", 8080, "application port")
	serHost := flag.String("host", "194.41.113.111", "server host")
	serPort := flag.Int("port", 5555, "server port")
	logLevel := flag.String("logLevel", "info", "application log level (debug, info, warn, error)")
	wlPath := flag.String(
		"whitelist",
		"whitelist.txt",
		"path to whitelist file",
	)
	flag.Parse()

	if _, ok := validLogLevels[*logLevel]; !ok {
		fmt.Fprintf(os.Stderr, "invalid logLevel: %q\n", *logLevel)
		os.Exit(1)
	}
	core.InitLogger(*logLevel)

	whitelist, err := loadWhitelist(*wlPath)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "whiteListSetup").
			Str("path", *wlPath).
			Msg("Failed to load whitelist")
	}

	cl := core.NewWindowsClient(*appHost, *appPort, whitelist)
	connected := cl.Connect(*serHost, *serPort)
	if connected == true {
		cl.Listen()
	} else {
		log.Fatal().
			Str("state", "starting").
			Str("host", *serHost).
			Int("port", *serPort).
			Msg("Can not connect to server")
	}
}

func loadWhitelist(path string) ([]string, error) {
	if err := ensureWhitelistFile(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	whitelist := make([]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue // comment in whitelist
		}

		whitelist = append(whitelist, line)
	}

	return whitelist, nil
}

func ensureWhitelistFile(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		err = os.WriteFile(path, []byte{}, 0644)
		if err != nil {
			return fmt.Errorf("failed to create whitelist file: %w", err)
		}
	}
	return err
}
