//go:build !windows

package linux

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"time"

	"github.com/Pos1t1veGuy/MoonVPN/core"
	"github.com/patrickmn/go-cache"
	"github.com/songgao/water"
)

type WaterAdapter struct {
	core.DefaultAdapter
	Interface *water.Interface
}

func NewWaterAdapter(name string) (*WaterAdapter, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(cfg)
	if err != nil {
		return nil, err
	}
	// rename interface
	if name != "" {
		switch runtime.GOOS {
		case "windows":
			core.ExecCmd("netsh", "interface", "set", "interface",
				fmt.Sprintf(`name="%s"`, iface.Name()),
				fmt.Sprintf(`newname="%s"`, name))
		case "linux":
			core.ExecCmd("ip", "link", "set", "dev", iface.Name(), "down")
			core.ExecCmd("ip", "link", "set", "dev", iface.Name(), "name", name)
			core.ExecCmd("ip", "link", "set", "dev", name, "up")
		case "darwin": // macOS: utun interfaces cannot be renamed
			name = iface.Name()
		}
	}

	time.Sleep(300 * time.Millisecond)
	Interface, err := net.InterfaceByName(name)
	if err != nil {
		log.Panicf("error get interface index: %v", err)
	}

	return &WaterAdapter{
		DefaultAdapter: core.DefaultAdapter{
			IfaceName:  name,
			IfaceIndex: Interface.Index,
		},
		Interface: iface,
	}, nil
}
func (adapter *WaterAdapter) Read(p []byte) (int, error) {
	return adapter.Interface.Read(p)
}

func (adapter *WaterAdapter) Write(b []byte) (int, error) {
	return adapter.Interface.Write(b)
}

func (adapter *WaterAdapter) Close() {
	adapter.Interface.Close()
}

func NewLinuxServer(addr string, port int, CIDR string) *core.Server {
	network, err := core.NewNetwork(CIDR)
	if err != nil {
		panic(err)
	}
	adapter, err := NewWaterAdapter("gotun0")
	if err != nil {
		panic(err)
	}

	return &core.Server{
		Endpoint:      *core.NewEndpoint(addr, port, CIDR),
		Peers:         make(map[string]*core.Peer),
		Cache:         cache.New(30*time.Minute, 10*time.Minute),
		Network:       network,
		Interface:     adapter,
		AnonymousPeer: core.NewPeer(nil, nil, false),
	}
}
