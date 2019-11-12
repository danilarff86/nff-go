package delegate

import (
	//"github.com/intel-go/nff-go/flow"
)

type EthPort uint16

type Packet struct {
}

type DPDKInterface struct {
}

func NewDPDKInterface() (error, *DPDKInterface) {
	return nil, new(DPDKInterface)
}

func (this *DPDKInterface) SendPacket(port EthPort, packet *Packet) error {
	return nil
}

func (this *DPDKInterface) RecvPacket(port EthPort) (error, *Packet) {
	return nil, nil
}
