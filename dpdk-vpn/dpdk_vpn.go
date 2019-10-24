package main

import (
	"encoding/json"
	"flag"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"log"
	"net"
	"os"
	"unsafe"
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
	flow.CheckFatal(flow.SetVectorHandler(firstFlow, myVectorHandler, PortContext{port: LanPort, config: &config.lan}))
	flow.CheckFatal(flow.SetSender(firstFlow, config.wan.ethPort))

	secondFlow, err := flow.SetReceiver(config.wan.ethPort)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetVectorHandler(secondFlow, myVectorHandler, PortContext{port: WanPort, config: &config.wan}))
	flow.CheckFatal(flow.SetSender(secondFlow, config.lan.ethPort))

	flow.CheckFatal(flow.SystemStart())
}

func myVectorHandler(curV []*packet.Packet, mask *[vecSize]bool, ctx flow.UserContext) {
	for i := uint(0); i < vecSize; i++ {
		if (*mask)[i] == true {
			(*mask)[i] = false

			portContext, ok := ctx.(PortContext)
			if !ok {
				println("Unable to upcast UserContext to PortContext")
			}

			pkt := curV[i]
			if pkt.Next != nil {
				log.Printf("\n\n\n//---------------\nHAS NEXT!!!\n//---------------\n\n\n\n")
			}
			//for pkt := curV[i]; pkt != nil; pkt = pkt.Next {
			pkt.ParseL3()
			arp := pkt.GetARPCheckVLAN()
			// ARP can be only in IPv4. IPv6 replace it with modified ICMP
			if arp != nil {
				if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest ||
					arp.THA != [types.EtherAddrLen]byte{} {
					continue
				}

				if types.ArrayToIPv4(arp.TPA) != portContext.config.local.ethIP {
					continue
				}

				// Prepare an answer to this request
				answerPacket, err := packet.NewPacket()
				if err != nil {
					common.LogFatal(common.Debug, err)
				}
				packet.InitARPReplyPacket(answerPacket, portContext.config.local.macAddr, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
				answerPacket.SendPacket(portContext.config.ethPort)
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
			//}
		}
	}
}

func encode(pkt *packet.Packet) bool {
	ipv4 := pkt.GetIPv4NoCheck()
	// Check that received ICMP packet is addressed at this host.
	if ipv4.DstAddr != config.lan.local.ethIP {
		return false
	}

	pkt.ParseL4ForIPv4()

	sndConf := config.wan

	pkt.Ether.DAddr = sndConf.remote.macAddr
	pkt.Ether.SAddr = sndConf.local.macAddr
	pkt.ParseL3()
	(pkt.GetIPv4NoCheck()).DstAddr = sndConf.remote.ethIP
	(pkt.GetIPv4NoCheck()).SrcAddr = sndConf.local.ethIP
	(pkt.GetIPv4NoCheck()).HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4NoCheck()))
	pkt.ParseL4ForIPv4()

	switch ipProto := (pkt.GetIPv4NoCheck()).NextProtoID; ipProto {
	case types.ICMPNumber:
		{
			//log.Printf("ICMP\n")
			pkt.ParseL7(types.ICMPNumber)
			(pkt.GetICMPNoCheck()).Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pkt.GetIPv4NoCheck(), pkt.GetICMPNoCheck(), pkt.Data))
		}
	case types.TCPNumber:
		{
			//log.Printf("TCP\n")
			pkt.Data = unsafe.Pointer(uintptr(pkt.L4) + uintptr(types.TCPMinLen))
			(pkt.GetTCPNoCheck()).Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pkt.GetIPv4NoCheck(), pkt.GetTCPNoCheck(), pkt.Data))
		}
	case types.UDPNumber:
		{
			//log.Printf("UDP\n")
			pkt.ParseL7(types.UDPNumber)
			(pkt.GetUDPNoCheck()).DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pkt.GetIPv4NoCheck(), pkt.GetUDPNoCheck(), pkt.Data))
		}
	default:
		return false
	}

	return true
}

func decode(pkt *packet.Packet) bool {
	ipv4 := pkt.GetIPv4NoCheck()
	// Check that received ICMP packet is addressed at this host.
	if ipv4.DstAddr != config.wan.local.ethIP {
		return false
	}

	pkt.ParseL4ForIPv4()

	sndConf := config.lan

	pkt.Ether.DAddr = sndConf.remote.macAddr
	pkt.Ether.SAddr = sndConf.local.macAddr
	pkt.ParseL3()
	(pkt.GetIPv4NoCheck()).DstAddr = sndConf.remote.ethIP
	(pkt.GetIPv4NoCheck()).SrcAddr = sndConf.local.ethIP
	(pkt.GetIPv4NoCheck()).HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4NoCheck()))
	pkt.ParseL4ForIPv4()

	switch ipProto := (pkt.GetIPv4NoCheck()).NextProtoID; ipProto {
	case types.ICMPNumber:
		{
			//log.Printf("ICMP\n")
			pkt.ParseL7(types.ICMPNumber)
			(pkt.GetICMPNoCheck()).Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(pkt.GetIPv4NoCheck(), pkt.GetICMPNoCheck(), pkt.Data))
		}
	case types.TCPNumber:
		{
			//log.Printf("TCP\n")
			pkt.Data = unsafe.Pointer(uintptr(pkt.L4) + uintptr(types.TCPMinLen))
			(pkt.GetTCPNoCheck()).Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pkt.GetIPv4NoCheck(), pkt.GetTCPNoCheck(), pkt.Data))
		}
	case types.UDPNumber:
		{
			//log.Printf("UDP\n")
			pkt.ParseL7(types.UDPNumber)
			(pkt.GetUDPNoCheck()).DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pkt.GetIPv4NoCheck(), pkt.GetUDPNoCheck(), pkt.Data))
		}
	default:
		return false
	}

	return true
}
