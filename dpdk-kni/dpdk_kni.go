// For forwarding testing call
// "insmod ./x86_64-native-linuxapp-gcc/kmod/rte_kni.ko lo_mode=lo_mode_fifo_skb"
// from DPDK directory before compiling this test. It will make a loop of packets
// inside KNI device and receive from KNI will receive all packets that were sent to KNI.

// For ping testing call
// "insmod ./x86_64-native-linuxapp-gcc/kmod/rte_kni.ko"
// from DPDK directory before compiling this test. Use --ping option.

// Other variants of rte_kni.ko configuration can be found here:
// http://dpdk.org/doc/guides/sample_app_ug/kernel_nic_interface.html

// Need to call "ifconfig myKNI 111.111.11.11" while running this example to allow other applications
// to receive packets from "111.111.11.11" address

package main

import (
	//"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
	//"log"
)

var ethMacAddr [types.EtherAddrLen]uint8
var ethPort uint16 = 0

func main() {
	config := flow.Config{
		// Is required for KNI
		NeedKNI: true,
		CPUList: "0-7",
	}

	flow.CheckFatal(flow.SystemInit(&config))
	// port of device, name of device
	kni, err := flow.CreateKniDevice(ethPort, "myKNI")
	flow.CheckFatal(err)

	ethMacAddr = flow.GetPortMACAddress(ethPort)

	inputFlow, err := flow.SetReceiver(ethPort)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(inputFlow, fromEthernetHandler, nil))
	flow.CheckFatal(flow.SetSenderKNI(inputFlow, kni))

	fromKNIFlow := flow.SetReceiverKNI(kni)
	flow.CheckFatal(flow.SetHandler(fromKNIFlow, fromKniHandler, nil))
	flow.CheckFatal(flow.SetSender(fromKNIFlow, ethPort))

	flow.CheckFatal(flow.SystemStart())
}

func fromKniHandler(pkt *packet.Packet, ctx flow.UserContext) {
	//log.Printf("Received packet from KNI %x\n", pkt.GetRawPacketBytes())
}

func fromEthernetHandler(pkt *packet.Packet, ctx flow.UserContext) {
	//log.Printf("Received packet from Ethernet %x\n", pkt.GetRawPacketBytes())

	/*pkt.ParseL3()
	arp := pkt.GetARPCheckVLAN()
	// ARP can be only in IPv4. IPv6 replace it with modified ICMP
	if arp != nil {
		if packet.SwapBytesUint16(arp.Operation) != packet.ARPRequest ||
			arp.THA != [types.EtherAddrLen]byte{} {
		}

		// Prepare an answer to this request
		answerPacket, err := packet.NewPacket()
		if err != nil {
			common.LogFatal(common.Debug, err)
		}
		packet.InitARPReplyPacket(answerPacket, ethMacAddr, arp.SHA, types.ArrayToIPv4(arp.TPA), types.ArrayToIPv4(arp.SPA))
		answerPacket.SendPacket(ethPort)
	}*/
}
