package main

import (
	"flag"
	"github.com/intel-go/nff-go/dpdk-fec/delegate"
	"github.com/intel-go/nff-go/dpdk-fec/impl"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"log"
)

var config delegate.Config

func main() {
	configFile := flag.String("config", "", "configuration file")
	mode := flag.String("mode", "VPN", "Working mode ('VPN' or 'NAT')")
	flag.Parse()

	err := config.Parse(*configFile)
	if err != nil {
		log.Fatalf("unable to load config: %+v\n", err)
	}

	log.Printf("Config: %+v\n", config)

	var myVectorHandler flow.VectorHandleFunction

	if *mode == "VPN" {
		myVectorHandler = impl.MyVpnVectorHandler
	} else if *mode == "NAT" {
		myVectorHandler = impl.MyNatVectorHandler
	} else if *mode == "DIRECT" {
		myVectorHandler = impl.MyDirectVectorHandler
	} else {
		log.Fatalf("Unsupported mode: '%s'\n", *mode)
	}

	dg := delegate.NewDPDKNetworkInterface()
	err = dg.Initialize(&config)
	if err != nil {
		log.Fatalf("unable to initialize dpdk interface: %+v\n", err)
	}

	var packets [32]*packet.Packet
	var mask [32]bool

	dg.StartProcessing(func() {
		/*for*/ {
			{
				err, pkt := dg.RecvPacket(delegate.EthPort(config.Wan.EthPort))
				if err != nil {
					log.Fatalf("RecvPacket(%d) returned error: %+v\n", int(config.Wan.EthPort), err)
				}
				if pkt != nil {
					packets[0] = pkt.Internal()
					mask[0] = true
					myVectorHandler(packets[:], &mask, impl.PortContext{Port: impl.WanPort, Config: &config})
					if mask[0] {
						err := dg.SendPacket(delegate.EthPort(config.Lan.EthPort), pkt)
						if err != nil {
							log.Fatalf("RecvPacket(%d) returned error: %+v\n", int(config.Lan.EthPort), err)
						}
					}
				}
			}
			{
				err, pkt := dg.RecvPacket(delegate.EthPort(config.Lan.EthPort))
				if err != nil {
					log.Fatalf("RecvPacket(%d) returned error: %+v\n", int(config.Lan.EthPort), err)
				}
				if pkt != nil {
					packets[0] = pkt.Internal()
					mask[0] = true
					myVectorHandler(packets[:], &mask, impl.PortContext{Port: impl.LanPort, Config: &config})
					if mask[0] {
						err := dg.SendPacket(delegate.EthPort(config.Wan.EthPort), pkt)
						if err != nil {
							log.Fatalf("RecvPacket(%d) returned error: %+v\n", int(config.Wan.EthPort), err)
						}
					}
				}
			}
			/*{
				err, pkt := dg.RecvPacket(0)
				if err != nil {
					log.Fatalf("RecvPacket(0) returned error: %+v\n", err)
				}
				if pkt != nil {
					err := dg.SendPacket(1, pkt)
					if err != nil {
						log.Fatalf("SendPacket(1) returned error: %+v\n", err)
					}
				}
			}

			{
				err, pkt := dg.RecvPacket(1)
				if err != nil {
					log.Fatalf("RecvPacket(1) returned error: %+v\n", err)
				}
				if pkt != nil {
					err := dg.SendPacket(0, pkt)
					if err != nil {
						log.Fatalf("SendPacket(0) returned error: %+v\n", err)
					}
				}
			}*/
		}
	})

	// UNUSED
	_ = myVectorHandler

	/*flow.CheckFatal(flow.SystemInit(nil))

	firstFlow, err := flow.SetReceiver(config.Lan.EthPort)
	flow.CheckFatal(err)
	//flow.CheckFatal(flow.SetHandler(firstFlow, handler, PortContext{port: LanPort, config: &config.lan}))
	flow.CheckFatal(flow.SetVectorHandler(firstFlow, myVectorHandler, impl.PortContext{Port: impl.LanPort, Config: &config}))
	//flow.CheckFatal(flow.SetStopper(firstFlow))
	flow.CheckFatal(flow.SetSender(firstFlow, config.Wan.EthPort))

	secondFlow, err := flow.SetReceiver(config.Wan.EthPort)
	flow.CheckFatal(err)
	//flow.CheckFatal(flow.SetHandler(secondFlow, handler, PortContext{port: WanPort, config: &config.wan}))
	flow.CheckFatal(flow.SetVectorHandler(secondFlow, myVectorHandler, impl.PortContext{Port: impl.WanPort, Config: &config}))
	//flow.CheckFatal(flow.SetStopper(secondFlow))
	flow.CheckFatal(flow.SetSender(secondFlow, config.Lan.EthPort))

	flow.CheckFatal(flow.SystemStart())*/
}
