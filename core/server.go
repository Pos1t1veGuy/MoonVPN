package core

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/patrickmn/go-cache"
)

type Server struct {
	Peers         map[string]*Peer
	mu            sync.RWMutex
	Cache         *cache.Cache
	Network       *Network
	AnonymousPeer *Peer
	Interface     InterfaceAdapter
	Endpoint
}

type Peer struct {
	VirtualIP  net.IP
	Addr       *net.UDPAddr
	LastSeen   time.Time
	Handshaked bool
}

func NewPeer(virtualIP net.IP, addr *net.UDPAddr, handshaked bool) *Peer {
	return &Peer{
		VirtualIP:  virtualIP,
		Addr:       addr,
		LastSeen:   time.Time{},
		Handshaked: handshaked,
	}
}

func (server *Server) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", server.FullAddr)
	if err != nil {
		return err
	}

	server.Conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	log.Printf("VPN server listening on %s", server.FullAddr)

	ConfigTunnel("", server.CIDR, "10.0.0.1", "gotun0")

	// interface => udp
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, err := server.Interface.Read(buffer)
			if err != nil || n == 0 {
				continue
			}

			version := buffer[0] >> 4
			fmt.Printf("IPv%d", version)
			switch version {
			case 4:
				gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
				ip4 := gop.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

				packet := Packet{
					Type:     0,
					AddrType: 4,
					SrcIP:    ip4.SrcIP,
					DstIP:    ip4.DstIP,
					Rsv:      [4]byte{0, 0, 0, 0},
					Length:   uint16(n),
					Data:     buffer[:n],
				}
				fmt.Println("received packet from", packet.SrcIP, "to", packet.DstIP)
				key := fmt.Sprintf("%v=>%v", packet.DstIP, packet.SrcIP)
				v, ok := server.Cache.Get(key)
				if ok {
					bytes, err := MarshalPacket(&packet)
					if err != nil {
						log.Println("error marshalling packet", err)
					}
					_, err = server.Conn.WriteToUDP(bytes, v.(*net.UDPAddr))
					if err != nil {
						log.Printf("WriteToUDP failed: %v", err)
					}
				} else {
					fmt.Println("KEY ERROR", key, server.Cache)
				}

			case 6:
				//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
				//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
				continue

			default:
				continue
			}
		}
	}()

	// udp => interface
	buf := make([]byte, 1500)
	for {
		n, clientAddr, err := server.Conn.ReadFromUDP(buf)
		if err != nil || n == 0 {
			log.Printf("udp read error: %v", err)
			continue
		}

		if _, found := server.Cache.Get(clientAddr.String()); !found {

			peer, err := server.Handshake(n, buf, clientAddr)
			if err != nil || !peer.Handshaked {
				log.Printf("handshake failed from %v: %v", clientAddr, err)
				continue
			}

			server.Cache.Set(
				clientAddr.String(),
				clientAddr,
				cache.DefaultExpiration,
			)

			log.Printf("new client handshaked: %v", clientAddr)
			continue
		}

		packet, err := UnmarshalPacket(buf[:n])
		if err != nil || packet.AddrType != 4 {
			log.Printf("UnmarshalPacket IPv%d failed: %v", packet.AddrType, err)
			continue
		}
		//DumpHex(buf[:n], len(buf[:n]))

		if _, err := server.Interface.Write(packet.Data); err != nil {
			continue
		}
		//DumpHex(packet.Data, len(packet.Data))

		fmt.Println("sent packet to", packet.DstIP, "from", packet.SrcIP)

		key := fmt.Sprintf("%v=>%v", packet.SrcIP, packet.DstIP)
		server.Cache.Set(key, clientAddr, cache.DefaultExpiration)
	}
}

type Network struct {
	Used    map[string]struct{}
	Current net.IP
	net.IPNet
}

func NewNetwork(cidr string) (*Network, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return &Network{
		Used:    map[string]struct{}{ip.String(): {}},
		Current: ip,
		IPNet:   *network,
	}, nil
}

func (network *Network) Next() (net.IP, error) {
	for {
		if !network.Contains(network.Current) {
			return nil, fmt.Errorf("no free IPs left")
		}

		ipStr := network.Current.String()
		if _, exists := network.Used[ipStr]; !exists {
			result := make(net.IP, len(network.Current))
			copy(result, network.Current)

			network.Used[ipStr] = struct{}{}
			network.increment()

			return result, nil
		}

		network.increment()
	}
}

func (network *Network) increment() {
	for i := len(network.Current) - 1; i >= 0; i-- {
		network.Current[i]++
		if network.Current[i] != 0 {
			break
		}
	}
}

// фрагментация UDP; шифрование; таймауты; старых peer надо чистить по lastseen; белые и черные списки; нормальный лог;
// аргументация в клиенте; сделать интерфейс врапперов; сделать базовый httpws враппер; присобачить нжинкс
// приделать базу данных; сделать из впна микросервис докер; присобачить бота; дописать страничку;
