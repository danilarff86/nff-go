package main

import "github.com/intel-go/nff-go/flow"
import "github.com/intel-go/nff-go/packet"
import "github.com/intel-go/nff-go/types"

//import "fmt"

type PortData struct {
	portNumber uint16
	neighCache *packet.NeighboursLookupTable
	macAddress types.MACAddress
	ipAddress  types.IPv4Address
}

func (pd PortData) Copy() interface{} {
	copy := PortData{portNumber: pd.portNumber, neighCache: pd.neighCache, macAddress: pd.macAddress, ipAddress: pd.ipAddress}
	return copy
}

func (pd PortData) Delete() {
}

var portData [2]PortData

func main() {
	config := flow.Config{
		CPUList:          "0-8",
		DisableScheduler: false,
	}
	flow.CheckFatal(flow.SystemInit(&config))

	initCommonState()

	for i := 0; i < len(portData); i++ {
		portData[i].portNumber = uint16(i)
		portData[i].macAddress = flow.GetPortMACAddress(uint16(i))
		portData[i].ipAddress = types.IPv4Address(192)<<24 | types.IPv4Address(168)<<16 | types.IPv4Address(1)<<8 | types.IPv4Address(140+i)
		portData[i].neighCache = packet.NewNeighbourTable(uint16(i), portData[i].macAddress,
			func(ipv4 types.IPv4Address) bool {
				return ipv4 == portData[i].ipAddress
			},
			func(ipv6 types.IPv6Address) bool {
				return false
			})
	}

	firstFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(firstFlow, handler, portData[0]))
	flow.CheckFatal(flow.SetStopper(firstFlow))
	//flow.CheckFatal(flow.SetSender(firstFlow, 1))

	secondFlow, err := flow.SetReceiver(1)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(secondFlow, handler, portData[1]))
	flow.CheckFatal(flow.SetStopper(secondFlow))
	//flow.CheckFatal(flow.SetSender(secondFlow, 0))

	flow.CheckFatal(flow.SystemStart())
}

func handler(current *packet.Packet, ctx flow.UserContext) {
	portData, ok := ctx.(PortData)
	if !ok {
		println("Unable to upcast UserContext")
	}

	for pkt := current; pkt != nil; pkt = pkt.Next {
		//fmt.Println("Handling pkt from port", portData.portNumber)
		//ipv4, _, _ := pkt.ParseAllKnownL3()
		//originalProtocol := pkt.Ether.EtherType

		/*if originalProtocol == types.SwapARPNumber {
			//arp := pkt.GetARPNoCheck()
			err := neighCache[0].HandleIPv4ARPPacket(pkt)
			if err != nil {
				fmt.Println(err)
			}
			continue
		}*/

		/*if ipv4 != nil {
			//fmt.Println(ipv4.String())
			found := false
			for i := 0; i < len(neighCache) && !found; i++ {
				dstMAC, found := neighCache[0].LookupMACForIPv4(ipv4.DstAddr)
				if found {
					fmt.Println("Found MAC address for IP", dstMAC.String())
				}
			}
			if !found {
				fmt.Println("Not found MAC address for IP", ipv4.DstAddr.String())
				for i := 0; i < len(neighCache) && !found; i++ {
					neighCache[i].SendARPRequestForIPv4(ipv4.DstAddr, nodeIP[i], 0)
				}
			}
		}*/

		pkt.SendPacket(portData.portNumber ^ 1)
	}
}
