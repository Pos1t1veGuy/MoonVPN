package core

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

func (client *Client) Handshake() (net.IP, error) {
	_, err := client.serverConn.Write([]byte{0x01, 0x01})

	if err != nil {
		return nil, fmt.Errorf("udp send error: %v", err)
	}

	buf := make([]byte, 1024)

	for {
		n, err := client.serverConn.Read(buf)
		if err != nil {
			return net.IP(buf[2:6]), fmt.Errorf("udp read error: %v", err)
		}

		if n < 6 {
			continue
		}

		if buf[0] != 0x02 || buf[1] != 0x00 {
			continue
		}

		ip := net.IP(buf[2:6])
		if ip.Equal(net.IPv4zero) {
			return nil, errors.New("server returned zero IP")
		}

		return ip, nil
	}
}

func (server *Server) Handshake(n int, buf []byte, addr *net.UDPAddr) (*Peer, error) {
	if n >= 2 && buf[0] == 0x01 && buf[1] == 0x01 {
		virtualIP, err := server.Network.Next()
		if err != nil {
			return server.AnonymousPeer, fmt.Errorf("get next virtual ip failed: %v", err)
		}

		resp := append([]byte{0x02, 0x00}, virtualIP.To4()...)
		_, err = server.Conn.WriteToUDP(resp, addr)
		if err != nil {
			return server.AnonymousPeer, fmt.Errorf("handshake response error: %v", err)
		}

		server.mu.Lock()
		server.Peers[addr.String()] = NewPeer(virtualIP, addr, true)
		server.mu.Unlock()

		return server.Peers[addr.String()], nil
	}
	return server.AnonymousPeer, errors.New("not a handshake")
}

// [PacketType:1][AddrType:1][SrcIP:4/16][DstIP:4/16][Rst:4][Length:2][Data:N]
type Packet struct {
	Type     byte   // (0 - default data packet, 1 - api packet, 2 - keepalive)
	AddrType byte   // (4 - IPv4, 6 - IPv6)
	SrcIP    net.IP // 4 or 16 bytes
	DstIP    net.IP // 4 or 16 bytes
	Rsv      [4]byte
	Length   uint16
	Data     []byte
}

func MarshalPacket(p *Packet) ([]byte, error) {
	buf := []byte{p.Type, p.AddrType}

	if p.AddrType == 4 {
		buf = append(buf, p.SrcIP.To4()...)
		buf = append(buf, p.DstIP.To4()...)
	} else if p.AddrType == 6 {
		buf = append(buf, p.SrcIP.To16()...)
		buf = append(buf, p.DstIP.To16()...)
	} else {
		return nil, fmt.Errorf("unknown address type: %v", p.AddrType)
	}
	buf = append(buf, p.Rsv[:]...)

	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, p.Length)
	buf = append(buf, lengthBytes...)

	buf = append(buf, p.Data...)

	return buf, nil
}
func UnmarshalPacket(data []byte) (*Packet, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("too short")
	}

	p := &Packet{
		Type:     data[0],
		AddrType: data[1],
	}

	ipLen := 4
	if p.AddrType == 6 {
		ipLen = 16
	}

	offset := 2
	p.SrcIP = net.IP(data[offset : offset+ipLen])
	offset += ipLen
	p.DstIP = net.IP(data[offset : offset+ipLen])
	offset += ipLen

	copy(p.Rsv[:], data[offset:offset+4])
	offset += 4

	p.Length = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	p.Data = data[offset:]

	return p, nil
}
