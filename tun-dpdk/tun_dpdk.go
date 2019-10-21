package main

import (
	"encoding/json"
	"flag"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"log"
	"net"
	"os"
)

const (
	tunName string = "tun0"
	txQLen  int    = 5000
	mtu     int    = 1500
)

type HostConfig struct {
	tunIP   net.IP
	ethIP   types.IPv4Address
	udpPort uint16
	macAddr [types.EtherAddrLen]uint8
}

type Config struct {
	local   HostConfig
	remote  HostConfig
	ethPort uint16
}

type hostConfigJSON struct {
	TunIP   string `json:"tun_ip"`
	EthIP   string `json:"eth_ip"`
	UDPPort uint16 `json:"udp_port"`
	MACAddr string `json:"mac_addr"`
}

type configJSON struct {
	Local   hostConfigJSON `json:"local"`
	Remote  hostConfigJSON `json:"remote"`
	ethPort uint16         `json:"eth_port"`
}

func parseIP(ipStr string) net.IP {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Fatalf("Unable to parse IP address: %s\n", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		log.Fatalf("Unable to parse IP address: %s\n", ipStr)
	}
	return ipv4
}

func parseHostConfig(inCfg hostConfigJSON) HostConfig {
	var outConf HostConfig
	outConf.tunIP = parseIP(inCfg.TunIP)
	outConf.ethIP = types.SliceToIPv4(parseIP(inCfg.EthIP))
	outConf.udpPort = inCfg.UDPPort
	mac, err := net.ParseMAC(inCfg.MACAddr)
	if err != nil {
		log.Fatalf("Unable to parse MAC address: %s, %+v\n", inCfg.MACAddr, err)
	}
	copy(outConf.macAddr[:], mac)
	return outConf
}

func loadConfiguration(file string) Config {
	var jsonConfig configJSON
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		log.Fatalf("Error opening config file: %+v\n", err)
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&jsonConfig)

	cfg := Config{
		local:   parseHostConfig(jsonConfig.Local),
		remote:  parseHostConfig(jsonConfig.Remote),
		ethPort: jsonConfig.ethPort,
	}

	log.Printf("ConfigJSON: %+v\n", jsonConfig)
	log.Printf("Config: %+v\n", cfg)
	return cfg
}

var config Config

var tunInterface *water.Interface
var tunRxPacket = make([]byte, mtu)

func main() {
	configFile := flag.String("config", "", "configuration file")
	flag.Parse()

	config = loadConfiguration(*configFile)

	flow.CheckFatal(flow.SystemInit(nil))

	inputFlow, err := flow.SetReceiver(config.ethPort)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetHandlerDrop(inputFlow, myHandler, nil))
	flow.CheckFatal(flow.SetStopper(inputFlow))

	config.local.macAddr = flow.GetPortMACAddress(config.ethPort)

	outputFlow := flow.SetGenerator(generatePacket, nil)
	flow.CheckFatal(flow.SetSender(outputFlow, config.ethPort))

	// TUN initialization
	createTun(config.local.tunIP)

	flow.CheckFatal(flow.SystemStart())
}

func createTun(ip net.IP) {
	var tunNetwork = &net.IPNet{IP: ip, Mask: []byte{255, 255, 255, 0}}

	var config = water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: tunName,
		},
	}

	var err error
	tunInterface, err = water.New(config)
	if nil != err {
		log.Fatalf("Tun interface init(), Unable to allocate TUN interface: %+v\n", err)
	}

	link, err := netlink.LinkByName(tunName)
	if nil != err {
		log.Fatalf("Tun interface %s Up(), Unable to get interface info %+v\n", tunName, err)
	}
	err = netlink.LinkSetMTU(link, mtu)
	if nil != err {
		log.Fatalf("Tun interface %s Up() Unable to set MTU to %d on interface\n", tunName, mtu)

	}
	err = netlink.LinkSetTxQLen(link, txQLen)
	if nil != err {
		log.Fatalf("Tun interface %s Up() Unable to set MTU to %d on interface\n", tunName, mtu)
	}
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: tunNetwork,
		Label: "",
	})
	if nil != err {
		log.Fatalf("Tun interface %s Up() Unable to set IP to %s / %s on interface: %+v\n", tunName, tunNetwork.IP.String(), tunNetwork.String(), err)
	}

	err = netlink.LinkSetUp(link)
	if nil != err {
		log.Fatalf("Tun interface Up() Unable to UP interface\n")
	}
	log.Printf("Tun interface %s Up() Tun(%s) interface with %s\n", tunName, tunNetwork.IP.String(), tunNetwork.String())
}

func generatePacket(pkt *packet.Packet, context flow.UserContext) {
	plen, err := tunInterface.Read(tunRxPacket)
	if err != nil {
		log.Fatalf("Tun Interface Read: type unknown %+v\n", err)
	}
	//log.Printf("Received TUN, payload %x\n", tunRxPacket[:plen])

	ok := packet.InitEmptyIPv4UDPPacket(pkt, uint(plen))
	if !ok {
		log.Fatalf("Unable to create UDP packet\n")
	}

	pkt.Ether.DAddr = config.remote.macAddr
	pkt.Ether.SAddr = config.local.macAddr
	pkt.ParseL3()
	(pkt.GetIPv4NoCheck()).DstAddr = config.remote.ethIP
	(pkt.GetIPv4NoCheck()).SrcAddr = config.local.ethIP
	pkt.ParseL4ForIPv4()
	(pkt.GetUDPNoCheck()).DstPort = packet.SwapBytesUint16(config.remote.udpPort)
	(pkt.GetUDPNoCheck()).SrcPort = packet.SwapBytesUint16(config.remote.udpPort)
	payload := (*[1 << 30]byte)(pkt.Data)[:plen]
	copy(payload, tunRxPacket[:plen])
	(pkt.GetIPv4NoCheck()).HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4NoCheck()))
	(pkt.GetUDPNoCheck()).DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pkt.GetIPv4NoCheck(), pkt.GetUDPNoCheck(), pkt.Data))

	//log.Printf("Sending UDP %x\n", pkt.GetRawPacketBytes())

	//pkt.SendPacket(myPort)
}

func myHandler(current *packet.Packet, context flow.UserContext) bool {
	current.ParseL3()
	arp := current.GetARPCheckVLAN()
	// ARP can be only in IPv4. IPv6 replace it with modified ICMP
	if arp != nil {
		if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest ||
			arp.THA != [types.EtherAddrLen]byte{} {
			return false
		}

		if types.ArrayToIPv4(arp.TPA) != config.local.ethIP {
			return false
		}

		// Prepare an answer to this request
		answerPacket, err := packet.NewPacket()
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		packet.InitARPReplyPacket(answerPacket, config.local.macAddr, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
		answerPacket.SendPacket(config.ethPort)

		return false
	}
	ipv4 := current.GetIPv4()
	if ipv4 != nil {
		current.ParseL4ForIPv4()
		if icmp := current.GetICMPForIPv4(); icmp != nil {
			// Check that received ICMP packet is echo request packet.
			if icmp.Type != types.ICMPTypeEchoRequest || icmp.Code != 0 {
				return true
			}

			// Check that received ICMP packet is addressed at this host.
			if ipv4.DstAddr != config.local.ethIP {
				return false
			}

			// Return a packet back to sender
			answerPacket, err := packet.NewPacket()
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			// TODO need to initilize new packet instead of copying
			packet.GeneratePacketFromByte(answerPacket, current.GetRawPacketBytes())
			answerPacket.Ether.DAddr = current.Ether.SAddr
			answerPacket.Ether.SAddr = current.Ether.DAddr
			answerPacket.ParseL3()
			(answerPacket.GetIPv4NoCheck()).DstAddr = ipv4.SrcAddr
			(answerPacket.GetIPv4NoCheck()).SrcAddr = ipv4.DstAddr
			answerPacket.ParseL4ForIPv4()
			(answerPacket.GetICMPNoCheck()).Type = types.ICMPTypeEchoResponse
			ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
			answerPacket.ParseL7(types.ICMPNumber)
			icmp.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(ipv4, icmp, answerPacket.Data))

			answerPacket.SendPacket(config.ethPort)

			return false
		} else if udp := current.GetUDPForIPv4(); udp != nil {
			if (ipv4.DstAddr != config.local.ethIP) || (packet.SwapBytesUint16(udp.DstPort) != config.local.udpPort) {
				return false
			}

			tunTxPacket, ok := current.GetPacketPayload()
			if !ok {
				log.Fatalf("Unable to read UDP payload\n")
			}
			//log.Printf("Received UDP %x\n", current.GetRawPacketBytes())
			_, err := tunInterface.Write(tunTxPacket)
			if err != nil {
				log.Fatalf("Tun Interface Write: type unknown %+v\n", err)
			}
			return false
		}
	}
	return true
}
