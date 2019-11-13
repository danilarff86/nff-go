package delegate

import (
	"github.com/intel-go/nff-go/packet"
)

type EthPort uint16

// should be taken from pool
type Packet struct {
	pkt *packet.Packet
}

func (this *Packet) Internal() *packet.Packet {
	return this.pkt
}

type ProcessingFunction func()

type NetworkInterface interface {
	Initialize(config *Config) error
	SendPacket(port EthPort, packet *Packet) error
	RecvPacket(port EthPort) (error, *Packet)
	StartProcessing(fn ProcessingFunction) error
}
