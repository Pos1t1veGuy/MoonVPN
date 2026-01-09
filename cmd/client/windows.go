//go:build windows

package main

import (
	"flag"

	"github.com/Pos1t1veGuy/MoonVPN/core/windows"
)

func main() {
	host := flag.String("host", "127.0.0.1", "application host")
	port := flag.Int("port", 8080, "application port")
	flag.Parse()

	cl := windows.NewClient(*host, *port, []string{"188.40.167.82"}, "10.0.0.1/24")
	cl.Connect("194.41.113.111", 5555)
}
