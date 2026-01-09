package core

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type Endpoint struct {
	Addr     string
	IP       net.IP
	Port     int
	FullAddr string
	CIDR     string

	Net  *net.IPNet
	Conn *net.UDPConn
}

func NewEndpoint(addr string, port int, CIDR string) *Endpoint {
	_, ipNet, err := net.ParseCIDR(CIDR)
	if err != nil {
		log.Panicf("error cidr %v", CIDR)
	}

	return &Endpoint{
		Addr:     addr,
		IP:       net.ParseIP(addr),
		Port:     port,
		FullAddr: fmt.Sprintf("%s:%d", addr, port),
		CIDR:     CIDR,
		Net:      ipNet,
	}
}

func ConfigTunnel(destinationIP string, netCidr string, interfaceIP string, IfaceName string) {
	ip, ipNet, err := net.ParseCIDR(netCidr)
	if err != nil {
		log.Panicf("error cidr %v", netCidr)
	}

	// destinationIP only for client to exclude server IP in routes
	switch runtime.GOOS {
	case "linux":
		if destinationIP != "" { // client
			ExecCmd("ip", "route", "add", destinationIP, "dev", "eth0")
		} else { // server
			ExecCmd("sysctl", "-w", "net.ipv4.ip_forward=1")
			ExecCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", netCidr, "-o", "eth0", "-j", "MASQUERADE")
		}

		ifaceMaskOnes, _ := ipNet.Mask.Size()
		ExecCmd("ip", "link", "set", "dev", IfaceName, "down")
		ExecCmd("ip", "addr", "flush", "dev", IfaceName)
		ExecCmd("ip", "addr", "add", fmt.Sprintf("%s/%d", interfaceIP, ifaceMaskOnes), "dev", IfaceName)

		ExecCmd("ip", "link", "set", "dev", IfaceName, "mtu", "1500")
		ExecCmd("ip", "link", "set", "dev", IfaceName, "up")
		//ExecCmd("ip", "route", "add", "1.1.1.1", "dev", IfaceName) // dns
	case "darwin":
		panic("конфигурация туннеля на дарвине не доделана =(")
	case "windows":
		ifaceMask := net.IP(ipNet.Mask).String()
		gatewayIP := ip.String()

		// getting interfaces info
		_, defIfaceIP, defIfaceIndex, err := getDefaultInterface()
		fmt.Println("default interface: Беспроводная сеть", defIfaceIP, defIfaceIndex)
		if err != nil {
			log.Panicf("error get default interface: %v", err)
		}
		curIface, err := net.InterfaceByName(IfaceName)
		if err != nil {
			log.Panicf("error get current interface index: %v", err)
		}
		fmt.Println("current interface:", IfaceName, interfaceIP, curIface.Index)

		// excluding route to remove connection loop
		if destinationIP != "" {
			ExecCmd("route", "add", destinationIP, "mask", "255.255.255.255", defIfaceIP.String(),
				"metric", "1", "if", strconv.Itoa(defIfaceIndex))
		}

		// add IP to interface
		ExecCmd("cmd", "/C",
			fmt.Sprintf(`netsh interface ipv4 set address name="%s" static %s mask=%s`, IfaceName, interfaceIP, ifaceMask))

		// set metric to interface
		ExecCmd("netsh", "interface", "ipv4", "set", "interface", strconv.Itoa(curIface.Index), "metric=1")

		//// add dns route
		//ExecCmd("netsh", "interface", "ipv4", "set", "dns", fmt.Sprintf("name=%d", IfaceName),
		//	fmt.Sprintf("static=%d", ip.String()))

		// add absolute route to interface (возможно стоит заменить gatewayIP на 0.0.0.0)
		ExecCmd("route", "add", "188.40.167.82", "mask", "255.255.255.255", gatewayIP, "metric", "1", "if", strconv.Itoa(curIface.Index))

	default:
		log.Printf("not support os:%v", runtime.GOOS)
	}
}

func ExecCmd(c string, args ...string) string {
	cmd := exec.Command(c, args...)
	var out bytes.Buffer
	cmd.Stderr = os.Stderr
	cmd.Stdout = &out
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if err != nil {
		log.Fatalln("failed to exec", cmd, "=>", err)
	}
	fmt.Println(cmd)
	return strings.TrimSpace(out.String())
}

func getDefaultInterface() (string, net.IP, int, error) {
	ifName := "Беспроводная сеть"

	ifIndexCmd := exec.Command(
		"powershell",
		"-Command",
		fmt.Sprintf("Get-NetAdapter -Name '%s' | Select-Object -First 1 -ExpandProperty InterfaceIndex", ifName),
	)
	ifIndexOut, err := ifIndexCmd.Output()
	if err != nil {
		return "", nil, 0, err
	}
	ifIndex, err := strconv.Atoi(strings.TrimSpace(string(ifIndexOut)))
	if err != nil {
		return "", nil, 0, err
	}

	gatewayCmd := exec.Command(
		"powershell",
		"-Command",
		"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop",
	)
	gatewayOut, err := gatewayCmd.Output()
	if err != nil {
		return "", nil, 0, err
	}
	gatewayIP := net.ParseIP(strings.TrimSpace(string(gatewayOut)))

	return ifName, gatewayIP, ifIndex, nil
}

type InterfaceAdapter interface {
	Name() string
	Index() int
	Read(p []byte) (int, error)
	Write(b []byte) (int, error)
	Close()
}

type DefaultAdapter struct {
	IfaceName  string
	IfaceIndex int
}

func (adapter *DefaultAdapter) Name() string {
	return adapter.IfaceName
}
func (adapter *DefaultAdapter) Index() int {
	return adapter.IfaceIndex
}

func DumpHex(packet []byte, n int) {
	for i := 0; i < n; i++ {
		fmt.Printf("%02x ", packet[i])
	}
	fmt.Println()
}

// SERVER NAT REQUIRED "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"
