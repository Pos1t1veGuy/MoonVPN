//go:build windows

package windows

import (
	"log"
	"net"
	"time"

	"github.com/Pos1t1veGuy/MoonVPN/core"
	"golang.zx2c4.com/wintun"
)

type WintunAdapter struct {
	core.DefaultAdapter

	Session wintun.Session
	Adapter *wintun.Adapter
}

func NewWintunAdapter(name string, sessionBufSize uint32) (*WintunAdapter, error) {
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		adapter, err = wintun.CreateAdapter(name, "Wintun", nil)
		if err != nil {
			return nil, err
		}
	}
	session, err := adapter.StartSession(sessionBufSize)
	if err != nil {
		return nil, err
	}

	time.Sleep(300 * time.Millisecond)
	Interface, err := net.InterfaceByName(name)
	if err != nil {
		log.Panicf("error get interface index: %v", err)
	}
	return &WintunAdapter{
		DefaultAdapter: core.DefaultAdapter{
			IfaceName:  name,
			IfaceIndex: Interface.Index,
		},
		Session: session,
		Adapter: adapter,
	}, nil
}

func (adapter *WintunAdapter) Read(p []byte) (int, error) {
	packet, err := adapter.Session.ReceivePacket()
	if err != nil {
		return 0, err
	}
	defer adapter.Session.ReleaseReceivePacket(packet)

	n := copy(p, packet)
	return n, nil
}

func (adapter *WintunAdapter) Write(b []byte) (int, error) {
	packet, err := adapter.Session.AllocateSendPacket(len(b))
	if err != nil {
		return 0, err
	}

	copy(packet, b)
	adapter.Session.SendPacket(packet)
	return len(b), nil
}

func (adapter *WintunAdapter) Close() {
	adapter.Session.End()
	adapter.Close()
}

func NewClient(addr string, port int, whiteList []string, CIDR string) *core.Client {
	adapter, err := NewWintunAdapter("gotun0", 8*1024*1024)
	if err != nil {
		panic(err)
	}
	return &core.Client{
		WhiteList: whiteList,
		Interface: adapter,
		Endpoint:  *core.NewEndpoint(addr, port, CIDR),
	}
}
