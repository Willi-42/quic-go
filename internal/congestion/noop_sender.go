package congestion

import (
	"math"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

type NoOpSendAlgorithm struct {
}

func (n NoOpSendAlgorithm) SetMaxDatagramSize(count protocol.ByteCount) {
}

func (n NoOpSendAlgorithm) TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time {
	return 0
}

func (n NoOpSendAlgorithm) HasPacingBudget(_ monotime.Time) bool {
	return true
}

func (n NoOpSendAlgorithm) OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
}

func (n NoOpSendAlgorithm) CanSend(bytesInFlight protocol.ByteCount) bool {
	return true
}

func (n NoOpSendAlgorithm) MaybeExitSlowStart() {
}

func (n NoOpSendAlgorithm) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time) {
}

func (n NoOpSendAlgorithm) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
}

func (n NoOpSendAlgorithm) OnRetransmissionTimeout(packetsRetransmitted bool) {
}

func (n NoOpSendAlgorithm) InSlowStart() bool {
	return false
}

func (n NoOpSendAlgorithm) InRecovery() bool {
	return false
}

func (n NoOpSendAlgorithm) GetCongestionWindow() protocol.ByteCount {
	return math.MaxInt64
}

func (c NoOpSendAlgorithm) SetPacerRate(b protocol.ByteCount) {
}
