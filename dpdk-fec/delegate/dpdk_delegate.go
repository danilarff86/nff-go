package delegate

import (
	//"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

type EthPort uint16

// should be taken from pool
type Packet struct {
	pkt *packet.Packet
}

type DPDKPortContext struct {
}

type DPDKInterface struct {
	ports map[EthPort]DPDKPortContext
}

func NewDPDKInterface() (error, *DPDKInterface) {
	instance := new(DPDKInterface)
	instance.ports = make(map[EthPort]DPDKPortContext)
	// Instantiate handlers
	// Create ring buffers
	// Organize port context data
	return nil, instance
}

func (this *DPDKInterface) SendPacket(port EthPort, packet *Packet) error {
	// recalculate all checksums
	// Set ip ADDR
	return nil
}

func (this *DPDKInterface) RecvPacket(port EthPort) (error, *Packet) {
	return nil, nil
}
