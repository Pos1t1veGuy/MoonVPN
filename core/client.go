package core

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Client struct {
	WhiteList  []string
	VirtualIP  net.IP
	serverConn *net.UDPConn
	Interface  InterfaceAdapter
	Endpoint
}

func (client *Client) Connect(addr string, port int) {
	serverAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		log.Println("failed to resolve server addr:", err)
		return
	}

	localAddr, err := net.ResolveUDPAddr("udp", client.FullAddr)
	if err != nil {
		log.Println("failed to get UDP socket:", err)
		return
	}

	client.Conn, err = net.DialUDP("udp", nil, localAddr)
	if err != nil {
		log.Println("failed to listen on UDP socket:", err)
		return
	}
	defer client.Conn.Close()

	client.serverConn, err = net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		panic(err)
	}
	defer client.serverConn.Close()

	log.Println("handshaking...")
	client.VirtualIP, err = client.Handshake()
	if err != nil {
		fmt.Println("error handshaking server:", err)
		return
	}
	fmt.Println("server got IP", client.VirtualIP)

	ConfigTunnel(addr, client.CIDR, client.VirtualIP.String(), client.Interface.Name())

	fmt.Println("client connected")
	go func() { // udp => interface
		buf := make([]byte, 1500)
		for {
			n, err := client.serverConn.Read(buf)
			if err != nil || n == 0 {
				continue
			}

			packet, err := UnmarshalPacket(buf[:n])
			if err != nil || packet.AddrType != 4 {
				log.Printf("UnmarshalPacket IPv%d failed: %v", packet.AddrType, err)
				continue
			}
			fmt.Println(1111, packet)
			DumpHex(packet.Data, len(packet.Data))
			client.Interface.Write(packet.Data)
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
					log.Println("failed to marshal packet:", err)
				}
				_, err = client.serverConn.Write(bytes)
				if err == nil {
					log.Println("sent packet")
				} else {
					log.Println("error sending packet", err)
				}
			}

		case 6:
			//gop := gopacket.NewPacket(buffer[:n], layers.LayerTypeIPv6, gopacket.NoCopy)
			//ip6 := gop.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
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
