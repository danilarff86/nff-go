package main

import (
	"flag"
	"github.com/intel-go/nff-go/dpdk-fec/delegate"
	"github.com/intel-go/nff-go/dpdk-fec/impl"
	"github.com/intel-go/nff-go/flow"
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

	err, dg := delegate.NewDPDKInterface()
	if err != nil {
		log.Fatalf("unable to create dpdk interface: %+v\n", err)
	}
	dg.SendPacket(0, nil)

	flow.CheckFatal(flow.SystemInit(nil))

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

	flow.CheckFatal(flow.SystemStart())
}
