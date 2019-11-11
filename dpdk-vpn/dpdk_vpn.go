package main

import (
	"encoding/json"
	"flag"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/internal/low"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"log"
	"net"
	"os"
	//"unsafe"
)

type HostConfig struct {
	ethIP   types.IPv4Address
	macAddr [types.EtherAddrLen]uint8
}

type PortConfig struct {
	local   HostConfig
	remote  HostConfig
	ethPort uint16
}

type Config struct {
	wan PortConfig
	lan PortConfig
}

type hostConfigJSON struct {
	EthIP   string `json:"eth_ip"`
	MACAddr string `json:"mac_addr"`
}

type portConfigJSON struct {
	Local   hostConfigJSON `json:"local"`
	Remote  hostConfigJSON `json:"remote"`
	EthPort uint16         `json:"eth_port"`
}

type configJSON struct {
	WAN portConfigJSON `json:"wan"`
	LAN portConfigJSON `json:"lan"`
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
	outConf.ethIP = types.SliceToIPv4(parseIP(inCfg.EthIP))
	mac, err := net.ParseMAC(inCfg.MACAddr)
	if err != nil {
		log.Fatalf("Unable to parse MAC address: %s, %+v\n", inCfg.MACAddr, err)
	}
	copy(outConf.macAddr[:], mac)
	return outConf
}

func parsePortConfig(inCfg portConfigJSON) PortConfig {
	return PortConfig{
		local:   parseHostConfig(inCfg.Local),
		remote:  parseHostConfig(inCfg.Remote),
		ethPort: inCfg.EthPort,
	}
}

func loadConfiguration(file string) Config {
	var jsonConfig configJSON
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		log.Fatalf("Error opening config file: %+v\n", err)
	}
	jsonParser := json.NewDecoder(configFile)
	err = jsonParser.Decode(&jsonConfig)
	if err != nil {
		log.Fatalf("unable to decode config: %+v\n", err)
	}

	cfg := Config{
		wan: parsePortConfig(jsonConfig.WAN),
		lan: parsePortConfig(jsonConfig.LAN),
	}

	log.Printf("ConfigJSON: %+v\n", jsonConfig)
	log.Printf("Config: %+v\n", cfg)
	return cfg
}

var config Config

const vecSize = 32

type EthPortEnum int

const (
	LanPort EthPortEnum = 0
	WanPort EthPortEnum = 1
)

type PortContext struct {
	port   EthPortEnum
	config *PortConfig
}

func (pc PortContext) Copy() interface{} {
	copy := PortContext{port: pc.port, config: pc.config}
	return copy
}

func (pc PortContext) Delete() {
}

func main() {
	configFile := flag.String("config", "", "configuration file")
	flag.Parse()

	config = loadConfiguration(*configFile)

	flow.CheckFatal(flow.SystemInit(nil))

	firstFlow, err := flow.SetReceiver(config.lan.ethPort)
	flow.CheckFatal(err)
	//flow.CheckFatal(flow.SetHandler(firstFlow, handler, PortContext{port: LanPort, config: &config.lan}))
	flow.CheckFatal(flow.SetVectorHandler(firstFlow, myVectorHandler, PortContext{port: LanPort, config: &config.lan}))
	//flow.CheckFatal(flow.SetStopper(firstFlow))
	flow.CheckFatal(flow.SetSender(firstFlow, config.wan.ethPort))

	secondFlow, err := flow.SetReceiver(config.wan.ethPort)
	flow.CheckFatal(err)
	//flow.CheckFatal(flow.SetHandler(secondFlow, handler, PortContext{port: WanPort, config: &config.wan}))
	flow.CheckFatal(flow.SetVectorHandler(secondFlow, myVectorHandler, PortContext{port: WanPort, config: &config.wan}))
	//flow.CheckFatal(flow.SetStopper(secondFlow))
	flow.CheckFatal(flow.SetSender(secondFlow, config.lan.ethPort))

	flow.CheckFatal(flow.SystemStart())
}

func myVectorHandler(curV []*packet.Packet, mask *[vecSize]bool, ctx flow.UserContext) {
	portContext, ok := ctx.(PortContext)
	if !ok {
		println("Unable to upcast UserContext to PortContext")
	}

	for i := uint(0); i < vecSize; i++ {
		if (*mask)[i] == true {
			(*mask)[i] = false

			pkt := curV[i]

			pkt.ParseL3()
			arp := pkt.GetARPCheckVLAN()
			// ARP can be only in IPv4. IPv6 replace it with modified ICMP
			if arp != nil {
				if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest ||
					arp.THA != [types.EtherAddrLen]byte{} {
					continue
				}

				/*if types.ArrayToIPv4(arp.TPA) != portContext.config.local.ethIP {
					return
				}*/

				// Prepare an answer to this request
				answerPacket, err := packet.NewPacket()
				if err != nil {
					common.LogFatal(common.Debug, err)
				}
				packet.InitARPReplyPacket(answerPacket, portContext.config.local.macAddr, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
				answerPacket.SendPacket(portContext.config.ethPort)

				continue
			}

			ipv4 := pkt.GetIPv4()
			if ipv4 != nil {
				switch portContext.port {
				case LanPort:
					//log.Printf("LAN IP Packet\n")
					(*mask)[i] = encode(pkt)
				case WanPort:
					//log.Printf("WAN IP Packet\n")
					(*mask)[i] = decode(pkt)
				}
			}
		}
	}
}

func encode(pkt *packet.Packet) bool {
	//log.Printf("Encoding Packet %x\n", pkt.GetRawPacketBytes())

	sndConf := config.wan

	ipPktLen := pkt.GetPacketLen() - types.EtherLen

	ipv4PktBytes := (*[1 << 30]byte)(pkt.L3)[:ipPktLen]
	answerPacketDataBytes := pkt.GetRawPacketBytes()[types.EtherLen+types.IPv4MinLen+types.UDPLen : types.EtherLen+types.IPv4MinLen+types.UDPLen+ipPktLen]
	for i := int(ipPktLen - 1); i >= 0; i-- {
		answerPacketDataBytes[i] = ipv4PktBytes[i]
	}
	//copy(answerPacketDataBytes, ipv4PktBytes)

	packet.InitEmptyIPv4UDPPacket(pkt, 0)
	low.TrimMbuf(pkt.CMbuf, types.EtherLen)

	pkt.Ether.DAddr = sndConf.remote.macAddr
	pkt.Ether.SAddr = sndConf.local.macAddr

	(pkt.GetIPv4NoCheck()).DstAddr = sndConf.remote.ethIP
	(pkt.GetIPv4NoCheck()).SrcAddr = sndConf.local.ethIP
	(pkt.GetIPv4NoCheck()).HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4NoCheck()))

	//answerPacket.ParseL7(types.UDPNumber)
	(pkt.GetUDPNoCheck()).DgramLen = packet.SwapBytesUint16(uint16(types.UDPLen + ipPktLen))
	(pkt.GetUDPNoCheck()).DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pkt.GetIPv4NoCheck(), pkt.GetUDPNoCheck(), pkt.Data))

	//log.Printf("Encoded Packet %x\n", pkt.GetRawPacketBytes())

	return true
}

func decode(pkt *packet.Packet) bool {
	//log.Printf("Decoding Packet %x\n", pkt.GetRawPacketBytes())

	ipv4 := pkt.GetIPv4NoCheck()
	// Check that received ICMP packet is addressed at this host.
	if ipv4.DstAddr != config.wan.local.ethIP {
		return false
	}

	pkt.ParseL4ForIPv4()

	udpPkt := pkt.GetUDPForIPv4()
	if udpPkt == nil {
		return false
	}

	pkt.ParseL7(types.UDPNumber)

	ipPktLen := packet.SwapBytesUint16(udpPkt.DgramLen) - types.UDPLen

	sndConf := config.lan

	pkt.Ether.EtherType = packet.SwapBytesUint16(types.IPV4Number)
	pkt.Ether.DAddr = sndConf.remote.macAddr
	pkt.Ether.SAddr = sndConf.local.macAddr

	ipv4PktBytes := (*[1 << 30]byte)(pkt.Data)[:ipPktLen]
	low.TrimMbuf(pkt.CMbuf, types.IPv4MinLen+types.UDPLen)
	answerPacketBytes := pkt.GetRawPacketBytes()[types.EtherLen : types.EtherLen+ipPktLen]
	copy(answerPacketBytes, ipv4PktBytes)

	//log.Printf("Decoded Packet %x\n", pkt.GetRawPacketBytes())

	return true
}
