package impl

import (
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/dpdk-fec/delegate"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	"unsafe"
)

const vecSize = 32

func MyNatVectorHandler(curV []*packet.Packet, mask *[vecSize]bool, ctx flow.UserContext) {
	portContext, ok := ctx.(PortContext)
	if !ok {
		println("Unable to upcast UserContext to PortContext")
	}

	var portConf *delegate.PortConfig
	var sndConf *delegate.PortConfig

	switch portContext.Port {
	case LanPort:
		portConf = &portContext.Config.Lan
		sndConf = &portContext.Config.Wan
	case WanPort:
		portConf = &portContext.Config.Wan
		sndConf = &portContext.Config.Lan
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

				if types.ArrayToIPv4(arp.TPA) != portConf.Local.EthIP {
					return
				}

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
				if ipv4.DstAddr != portConf.Local.EthIP {
					continue
				}

				(*mask)[i] = true

				pkt.ParseL4ForIPv4()

				pkt.Ether.DAddr = sndConf.Remote.MacAddr
				pkt.Ether.SAddr = sndConf.Local.MacAddr
				pkt.ParseL3()
				(pkt.GetIPv4NoCheck()).DstAddr = sndConf.Remote.EthIP
				(pkt.GetIPv4NoCheck()).SrcAddr = sndConf.Local.EthIP
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
					(*mask)[i] = false
				}
			}
		}
	}
}
