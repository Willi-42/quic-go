package congestion

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// The pacer implements a token bucket pacing algorithm.
type ratePacer struct {
	limit           *Limiter
	maxDatagramSize protocol.ByteCount
}

func newRatePacer() *ratePacer {
	p := &ratePacer{
		limit:           NewLimiter(Limit(750_000), 1500*8),
		maxDatagramSize: initialMaxDatagramSize,
	}
	return p
}

func (p *ratePacer) SentPacket(sendTime monotime.Time, size protocol.ByteCount) {
	r := p.limit.ReserveN(sendTime, int(size*8))
	if !r.OK() {
		r.Cancel()
	}
}

func (p *ratePacer) Budget(now monotime.Time) protocol.ByteCount {
	// the caller of Budget only cares if we can send maxDatagramSize or not
	r := p.limit.ReserveN(now, int(p.maxDatagramSize*8))
	if !r.OK() {
		return 0
	}

	delay := r.DelayFrom(now)
	r.CancelAt(now) // don't consume the tokens yet; just checking

	if delay <= 0 {
		return p.maxDatagramSize // tokens available now
	}

	return 0 // not enough tokens yet
}

// TimeUntilSend returns when the next packet should be sent.
// It returns zero if a packet can be sent immediately.
func (p *ratePacer) TimeUntilSend() monotime.Time {
	r := p.limit.ReserveN(monotime.Now(), int(p.maxDatagramSize*8))
	if !r.OK() {
		// should not happen (maxDatagram smaller than burst size)
		return 0
	}

	delay := r.Delay()
	r.Cancel() // don't consume the tokens yet; just checking

	if delay <= 0 {
		return 0 // send immediately
	}
	return monotime.Now().Add(delay)
}

func (p *ratePacer) SetMaxDatagramSize(s protocol.ByteCount) {
	p.maxDatagramSize = s
}

func (p *ratePacer) SetRate(r protocol.ByteCount) {
	rateBits := int(r * 8)
	p.limit.SetLimit(Limit(rateBits))
	dynamicBurst := 8 * (float64(rateBits) / 200)
	burst := max(int(dynamicBurst), int(p.maxDatagramSize*8)) // ensure that burst does not get too small
	p.limit.SetBurst(burst)
}
