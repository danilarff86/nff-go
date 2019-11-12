package impl

import (
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/dpdk-fec/delegate"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"github.com/intel-go/nff-go/internal/low"
)

func MyVpnVectorHandler(curV []*packet.Packet, mask *[vecSize]bool, ctx flow.UserContext) {
	portContext, ok := ctx.(PortContext)
	if !ok {
		println("Unable to upcast UserContext to PortContext")
	}

	var portConf *delegate.PortConfig

	switch portContext.Port {
	case LanPort:
		portConf = &portContext.Config.Lan
	case WanPort:
		portConf = &portContext.Config.Wan
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
				packet.InitARPReplyPacket(answerPacket, portConf.Local.MacAddr, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
				answerPacket.SendPacket(portConf.EthPort)

				continue
			}

			ipv4 := pkt.GetIPv4()
			if ipv4 != nil {
				switch portContext.Port {
				case LanPort:
					//log.Printf("LAN IP Packet\n")
					(*mask)[i] = encode(pkt, portContext.Config)
				case WanPort:
					//log.Printf("WAN IP Packet\n")
					(*mask)[i] = decode(pkt, portContext.Config)
				}
			}
		}
	}
}

func encode(pkt *packet.Packet, config *delegate.Config) bool {
	//log.Printf("Encoding Packet %x\n", pkt.GetRawPacketBytes())

	sndConf := config.Wan

	ipPktLen := pkt.GetPacketLen() - types.EtherLen

	ipv4PktBytes := (*[1 << 30]byte)(pkt.L3)[:ipPktLen]
	answerPacketDataBytes := pkt.GetRawPacketBytes()[types.EtherLen+types.IPv4MinLen+types.UDPLen : types.EtherLen+types.IPv4MinLen+types.UDPLen+ipPktLen]
	for i := int(ipPktLen - 1); i >= 0; i-- {
		answerPacketDataBytes[i] = ipv4PktBytes[i]
	}
	//copy(answerPacketDataBytes, ipv4PktBytes)

	packet.InitEmptyIPv4UDPPacket(pkt, 0)
	low.TrimMbuf(pkt.CMbuf, types.EtherLen)

	pkt.Ether.DAddr = sndConf.Remote.MacAddr
	pkt.Ether.SAddr = sndConf.Local.MacAddr

	(pkt.GetIPv4NoCheck()).DstAddr = sndConf.Remote.EthIP
	(pkt.GetIPv4NoCheck()).SrcAddr = sndConf.Local.EthIP
	(pkt.GetIPv4NoCheck()).HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(pkt.GetIPv4NoCheck()))

	//answerPacket.ParseL7(types.UDPNumber)
	(pkt.GetUDPNoCheck()).DgramLen = packet.SwapBytesUint16(uint16(types.UDPLen + ipPktLen))
	(pkt.GetUDPNoCheck()).DgramCksum = packet.SwapBytesUint16(packet.CalculateIPv4UDPChecksum(pkt.GetIPv4NoCheck(), pkt.GetUDPNoCheck(), pkt.Data))

	//log.Printf("Encoded Packet %x\n", pkt.GetRawPacketBytes())

	return true
}

func decode(pkt *packet.Packet, config *delegate.Config) bool {
	//log.Printf("Decoding Packet %x\n", pkt.GetRawPacketBytes())

	sndConf := config.Lan

	ipv4 := pkt.GetIPv4NoCheck()
	// Check that received ICMP packet is addressed at this host.
	if ipv4.DstAddr != config.Wan.Local.EthIP {
		return false
	}

	pkt.ParseL4ForIPv4()

	udpPkt := pkt.GetUDPForIPv4()
	if udpPkt == nil {
		return false
	}

	pkt.ParseL7(types.UDPNumber)

	ipPktLen := packet.SwapBytesUint16(udpPkt.DgramLen) - types.UDPLen

	pkt.Ether.EtherType = packet.SwapBytesUint16(types.IPV4Number)
	pkt.Ether.DAddr = sndConf.Remote.MacAddr
	pkt.Ether.SAddr = sndConf.Local.MacAddr

	ipv4PktBytes := (*[1 << 30]byte)(pkt.Data)[:ipPktLen]
	low.TrimMbuf(pkt.CMbuf, types.IPv4MinLen+types.UDPLen)
	answerPacketBytes := pkt.GetRawPacketBytes()[types.EtherLen : types.EtherLen+ipPktLen]
	copy(answerPacketBytes, ipv4PktBytes)

	//log.Printf("Decoded Packet %x\n", pkt.GetRawPacketBytes())

	return true
}
