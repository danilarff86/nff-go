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
	ports []PortConfig
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

type configJSON []portConfigJSON

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

	if len(jsonConfig) != 2 {
		log.Fatalf("Wrong config: %+v\n, %+v\n", jsonConfig, err)
	}
	cfg := Config{}

	for _, portCfg := range jsonConfig {
		cfg.ports = append(cfg.ports, parsePortConfig(portCfg))
	}

	log.Printf("ConfigJSON: %+v\n", jsonConfig)
	log.Printf("Config: %+v\n", cfg)
	return cfg
}

var config Config

type PortContext struct {
	index int
}

func (pc PortContext) Copy() interface{} {
	copy := PortContext{index: pc.index}
	return copy
}

func (pc PortContext) Delete() {
}

func main() {
	configFile := flag.String("config", "", "configuration file")
	flag.Parse()

	config = loadConfiguration(*configFile)

	flow.CheckFatal(flow.SystemInit(nil))

	firstFlow, err := flow.SetReceiver(config.ports[0].ethPort)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(firstFlow, handler, PortContext{index: 0}))
	flow.CheckFatal(flow.SetStopper(firstFlow))

	secondFlow, err := flow.SetReceiver(config.ports[1].ethPort)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(secondFlow, handler, PortContext{index: 1}))
	flow.CheckFatal(flow.SetStopper(secondFlow))

	flow.CheckFatal(flow.SystemStart())
}

func handler(current *packet.Packet, ctx flow.UserContext) {
	portContext, ok := ctx.(PortContext)
	if !ok {
		println("Unable to upcast UserContext to PortContext")
	}

	for pkt := current; pkt != nil; pkt = pkt.Next {

		pkt.ParseL3()
		arp := pkt.GetARPCheckVLAN()
		// ARP can be only in IPv4. IPv6 replace it with modified ICMP
		if arp != nil {
			if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest ||
				arp.THA != [types.EtherAddrLen]byte{} {
				return
			}

			if types.ArrayToIPv4(arp.TPA) != config.ports[portContext.index].local.ethIP {
				return
			}

			// Prepare an answer to this request
			answerPacket, err := packet.NewPacket()
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			packet.InitARPReplyPacket(answerPacket, config.ports[portContext.index].local.macAddr, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
			answerPacket.SendPacket(config.ports[portContext.index].ethPort)

			return
		}

		/*ipv4 := pkt.GetIPv4()
		if ipv4 != nil {
			pkt.ParseL4ForIPv4()
			if icmp := pkt.GetICMPForIPv4(); icmp != nil {
				// Check that received ICMP packet is echo request packet.
				if icmp.Type != types.ICMPTypeEchoRequest || icmp.Code != 0 {
					return
				}

				// Check that received ICMP packet is addressed at this host.
				if ipv4.DstAddr != config.ports[portContext.index].local.ethIP {
					return
				}

				// Return a packet back to sender
				answerPacket, err := packet.NewPacket()
				if err != nil {
					common.LogFatal(common.Debug, err)
				}
				// TODO need to initilize new packet instead of copying
				packet.GeneratePacketFromByte(answerPacket, pkt.GetRawPacketBytes())
				answerPacket.Ether.DAddr = pkt.Ether.SAddr
				answerPacket.Ether.SAddr = pkt.Ether.DAddr
				answerPacket.ParseL3()
				(answerPacket.GetIPv4NoCheck()).DstAddr = ipv4.SrcAddr
				(answerPacket.GetIPv4NoCheck()).SrcAddr = ipv4.DstAddr
				answerPacket.ParseL4ForIPv4()
				(answerPacket.GetICMPNoCheck()).Type = types.ICMPTypeEchoResponse
				ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
				answerPacket.ParseL7(types.ICMPNumber)
				icmp.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(ipv4, icmp, answerPacket.Data))

				answerPacket.SendPacket(config.ports[portContext.index].ethPort)

				return
			}
		}*/
		ipv4 := pkt.GetIPv4()
		if ipv4 != nil {
			// Check that received ICMP packet is addressed at this host.
			if ipv4.DstAddr != config.ports[portContext.index].local.ethIP {
				return
			}

			pkt.ParseL4ForIPv4()

			sndConf := config.ports[portContext.index^1]

			answerPacket, err := packet.NewPacket()
			if err != nil {
				common.LogFatal(common.Debug, err)
			}
			// TODO need to initilize new packet instead of copying
			packet.GeneratePacketFromByte(answerPacket, pkt.GetRawPacketBytes())

			answerPacket.Ether.DAddr = sndConf.remote.macAddr
			answerPacket.Ether.SAddr = sndConf.local.macAddr
			answerPacket.ParseL3()
			(answerPacket.GetIPv4NoCheck()).DstAddr = sndConf.remote.ethIP
			(answerPacket.GetIPv4NoCheck()).SrcAddr = sndConf.local.ethIP
			(answerPacket.GetIPv4NoCheck()).HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(answerPacket.GetIPv4NoCheck()))
			answerPacket.ParseL4ForIPv4()

			switch ipProto := (answerPacket.GetIPv4NoCheck()).NextProtoID; ipProto {
			case types.ICMPNumber:
				{
					//log.Printf("ICMP\n")
					answerPacket.ParseL7(types.ICMPNumber)
					(answerPacket.GetICMPNoCheck()).Cksum = packet.SwapBytesUint16(packet.CalculateIPv4ICMPChecksum(answerPacket.GetIPv4NoCheck(), answerPacket.GetICMPNoCheck(), answerPacket.Data))
				}
			case types.TCPNumber:
				{
					//log.Printf("TCP\n")
					//answerPacket.ParseL7(types.TCPNumber)
					answerPacket.Data = unsafe.Pointer(uintptr(answerPacket.L4) + uintptr(types.TCPMinLen))
					(answerPacket.GetTCPNoCheck()).Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(answerPacket.GetIPv4NoCheck(), answerPacket.GetTCPNoCheck(), answerPacket.Data))

					/*log.Printf("TCP data offset: %d\n", (((*packet.TCPHdr)(pkt.L4)).DataOff&0xf0)>>3)

					pkt.ParseL7(types.TCPNumber)
					tcpPacket := pkt.GetTCPForIPv4()
					originCksum := tcpPacket.Cksum
					tcpPacket.Cksum = 0
					pkt.Data = unsafe.Pointer(uintptr(pkt.L4) + uintptr((((*packet.TCPHdr)(pkt.L4)).DataOff&0xf0)>>3))
					tcpPacket.Cksum = packet.SwapBytesUint16(packet.CalculateIPv4TCPChecksum(pkt.GetIPv4(), tcpPacket, pkt.Data))
					log.Printf("TCP checksum. Origin: %d, Recalculated %d\n", originCksum, tcpPacket.Cksum)*/
				}
			case types.UDPNumber:
				{
					//log.Printf("UDP\n")
					answerPacket.ParseL7(types.UDPNumber)
					(answerPacket.GetUDPNoCheck()).DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(answerPacket.GetIPv4NoCheck(), answerPacket.GetUDPNoCheck(), answerPacket.Data))
				}
			default:
				return
			}

			answerPacket.SendPacket(sndConf.ethPort)
		}
	}
}
