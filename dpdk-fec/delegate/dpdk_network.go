package delegate

import (
	"fmt"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	lfqueue "github.com/xiaonanln/go-lockfree-queue"
)

const vecSize = 32
const sizeMultiplier = 64

type dpdkPortContext struct {
	config PortConfig
	rxRing *lfqueue.Queue
}

func (pc dpdkPortContext) Copy() interface{} {
	copy := dpdkPortContext{config: pc.config, rxRing: pc.rxRing}
	return copy
}

func (pc dpdkPortContext) Delete() {
}

type processingFunctionWrapper struct {
	fn ProcessingFunction
}

func (pc processingFunctionWrapper) Copy() interface{} {
	copy := processingFunctionWrapper{fn: pc.fn}
	return copy
}

func (pc processingFunctionWrapper) Delete() {
}

type dpdkNetworkInterface struct {
	ports []*dpdkPortContext
}

func NewDPDKNetworkInterface() NetworkInterface {
	return new(dpdkNetworkInterface)
}

func (this *dpdkNetworkInterface) Initialize(config *Config) error {
	this.ports = make([]*dpdkPortContext, 2)
	this.ports[0] = &dpdkPortContext{config: config.Wan, rxRing: lfqueue.NewQueue(vecSize * sizeMultiplier)}
	this.ports[1] = &dpdkPortContext{config: config.Lan, rxRing: lfqueue.NewQueue(vecSize * sizeMultiplier)}

	flow.CheckFatal(flow.SystemInit(nil))

	wanFlow, err := flow.SetReceiver(config.Wan.EthPort)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(wanFlow, handler, this.ports[0]))
	flow.CheckFatal(flow.SetStopper(wanFlow))

	lanFlow, err := flow.SetReceiver(config.Lan.EthPort)
	flow.CheckFatal(err)
	flow.CheckFatal(flow.SetHandler(lanFlow, handler, this.ports[1]))
	flow.CheckFatal(flow.SetStopper(lanFlow))

	return nil
}

func (this *dpdkNetworkInterface) SendPacket(port EthPort, packet *Packet) error {
	if int(port) >= len(this.ports) {
		return delegateError{s: fmt.Sprintf("Wrong port number: %d", port)}
	}

	packet.pkt.SendPacket(this.ports[int(port)].config.EthPort)

	// TODO: recalculate all checksums
	// TODO: set ip ADDR
	return nil
}

func (this *dpdkNetworkInterface) RecvPacket(port EthPort) (error, *Packet) {
	if int(port) >= len(this.ports) {
		return delegateError{s: fmt.Sprintf("Wrong port number: %d", port)}, nil
	}
	rcvPkt, ok := this.ports[int(port)].rxRing.Get()
	if ok {
		return nil, &Packet{pkt: rcvPkt.(*packet.Packet)}
	}
	return nil, nil
}

func (this *dpdkNetworkInterface) StartProcessing(fn ProcessingFunction) error {
	// TODO: Avoid using NFF-GO NUMA Node
	fakeFlow := flow.SetGenerator(processing, processingFunctionWrapper{fn: fn})
	flow.CheckFatal(flow.SetStopper(fakeFlow))

	flow.CheckFatal(flow.SystemStart())

	return nil
}

func processing(pkt *packet.Packet, context flow.UserContext) {
	fnWrapper, ok := context.(processingFunctionWrapper)
	if !ok {
		common.LogFatal(common.Debug, delegateError{s: "Unable to upcast UserContext to processingFunctionWrapper"})
	}

	fnWrapper.fn()
}

func handler(pkt *packet.Packet, ctx flow.UserContext) {
	portContext, ok := ctx.(dpdkPortContext)
	if !ok {
		common.LogFatal(common.Debug, delegateError{s: "Unable to upcast UserContext to portContext"})
	}

	// TODO: Optimize, retrieve packet from POOL
	rcvPkt, err := packet.NewPacket()
	if err != nil {
		common.LogFatal(common.Debug, err)
	}

	packet.GeneratePacketFromByte(rcvPkt, pkt.GetRawPacketBytes())

	portContext.rxRing.Put(rcvPkt)
}
