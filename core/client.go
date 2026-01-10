package core

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

type Client struct {
	WhiteList  []string
	VirtualIP  net.IP
	serverConn *net.UDPConn
	Interface  InterfaceAdapter
	Endpoint
}

func (client *Client) Connect(addr string, port int) {
	serverAddrFormatted := fmt.Sprintf("%s:%d", addr, port)
	serverAddr, err := net.ResolveUDPAddr("udp", serverAddrFormatted)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("serverAddr", serverAddrFormatted).
			Msg("Failed to resolve server address")
		return
	}

	localAddr, err := net.ResolveUDPAddr("udp", client.FullAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("localAddr", client.FullAddr).
			Msg("Failed to resolve local address")
		return
	}

	client.Conn, err = net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("localAddr", client.FullAddr).
			Msg("Failed to create a local server")
		return
	}
	defer client.Conn.Close()

	client.serverConn, err = net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("serverAddr", serverAddrFormatted).
			Msg("Failed to connect to server")
	}
	defer client.serverConn.Close()

	log.Info().Str("ServerAddr", serverAddrFormatted).Msg("Connected to server")
	client.VirtualIP, err = client.Handshake()
	if err != nil {
		log.Fatal().
			Err(err).
			Str("state", "connecting").
			Str("serverAddr", serverAddrFormatted).
			Msg("Failed to handshake client")
		return
	}
	log.Debug().
		Str("state", "connecting").
		Str("IP", client.VirtualIP.String()).
		Msg("Client connected to server")

	ConfigTunnel(addr, client.CIDR, client.VirtualIP.String(), client.Interface.Name(), client.WhiteList)
	log.Info().
		Str("state", "connecting").
		Str("Net", client.CIDR).
		Msg("Tunnel created")

	go func() { // udp => interface
		buf := make([]byte, 1500)
		for {
			n, err := client.serverConn.Read(buf)
			if err != nil || n == 0 {
				continue
			}

			packet, err := UnmarshalPacket(buf[:n])
			if err != nil || packet.AddrType != 4 {
				log.Debug().
					Err(err).
					Str("state", "U2I").
					Int("len", n).
					Int("AddrType", int(packet.AddrType)).
					Msg("(UDP=>Interface) Cannot unmarshal packet")
				continue
			}
			if _, err = client.Interface.Write(packet.Data); err != nil {
				log.Debug().
					Err(err).
					Str("state", "U2I").
					Int("len", n).
					Int("AddrType", int(packet.AddrType)).
					Msg("(UDP=>Interface) Cannot send packet")
			} else {
				log.Debug().
					Str("state", "U2I").
					Int("len", n).
					Int("AddrType", int(packet.AddrType)).
					Msg("(UDP=>Interface) Sent a packet")
			}
		}
	}()

	// interface => udp
	buffer := make([]byte, 1500)
	for {
		n, err := client.Interface.Read(buffer)
		if err != nil || n == 0 {
			continue
		}

		version := buffer[0] >> 4
		switch version {
		case 4:
			gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
			ip4 := gop.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			if client.FilterIPs4(ip4) {
				packet := Packet{
					Type:     0,
					AddrType: 4,
					SrcIP:    ip4.SrcIP,
					DstIP:    ip4.DstIP,
					Rsv:      [4]byte{0, 0, 0, 0},
					Length:   uint16(n),
					Data:     buffer[:n],
				}
				bytes, err := MarshalPacket(&packet)
				if err != nil {
					log.Debug().
						Err(err).
						Str("state", "I2U").
						Int("len", n).
						Int("AddrType", int(packet.AddrType)).
						Msg("(UDP<=Interface) Failed to marshal packet")
					continue
				}
				if _, err = client.serverConn.Write(bytes); err != nil {
					log.Debug().
						Err(err).
						Str("state", "I2U").
						Int("len", n).
						Int("AddrType", int(packet.AddrType)).
						Msg("(UDP<=Interface) Failed to send packet")
				} else {
					log.Debug().
						Str("state", "I2U").
						Int("len", n).
						Int("AddrType", int(packet.AddrType)).
						Msg("(UDP<=Interface) Sent a packet")
				}
			}

		case 6:
			//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
			//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			//log.Warn().
			//	Int("len", n).
			//	Str("state", "I2U").
			//	Int("AddrType", int(version)).
			//	Msg("(UDP<=Interface) IPv6 not supported")
			continue

		default:
			continue
		}
	}
}

func (client *Client) FilterIPs4(packet *layers.IPv4) bool {
	return !packet.DstIP.IsMulticast() && !packet.DstIP.IsLinkLocalUnicast() && !packet.DstIP.IsLoopback() &&
		!packet.DstIP.Equal(net.IPv4bcast) && !packet.DstIP.Equal(client.VirtualIP) &&
		!packet.DstIP.Equal(client.Net.IP) && !isSubnetBroadcast(packet.DstIP, client.Net)
}
func isSubnetBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = ipNet.IP[i] | ^ipNet.Mask[i]
	}

	return ip4.Equal(broadcast)
}
