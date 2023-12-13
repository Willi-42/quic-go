package ackhandler

import "github.com/lucas-clemente/quic-go/internal/wire"

type Frame struct {
	wire.Frame // nil if the frame has already been acknowledged in another packet
	OnLost     func(wire.Frame, uint64)
	OnAcked    func(wire.Frame, uint64)
}
