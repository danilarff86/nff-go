package impl

import (
	"github.com/intel-go/nff-go/dpdk-fec/delegate"
)

type EthPortEnum int

const (
	LanPort EthPortEnum = 0
	WanPort EthPortEnum = 1
)

type PortContext struct {
	Port   EthPortEnum
	Config *delegate.Config
}

func (pc PortContext) Copy() interface{} {
	copy := PortContext{Port: pc.Port, Config: pc.Config}
	return copy
}

func (pc PortContext) Delete() {
}