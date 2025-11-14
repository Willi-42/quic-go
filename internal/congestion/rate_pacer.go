package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"golang.org/x/time/rate"
)

// The pacer implements a token bucket pacing algorithm.
type ratePacer struct {
	limit           *rate.Limiter
	maxDatagramSize protocol.ByteCount
}

func newRatePacer() *ratePacer {
	p := &ratePacer{
		limit:           rate.NewLimiter(rate.Limit(750_000), 1500*8),
		maxDatagramSize: initialMaxDatagramSize,
	}
	return p
}

func (p *ratePacer) SentPacket(sendTime monotime.Time, size protocol.ByteCount) {
	r := p.limit.ReserveN(time.Now(), int(size*8))
	if !r.OK() {
		r.Cancel()
	}
}

func (p *ratePacer) Budget(now monotime.Time) protocol.ByteCount {
	tokens := p.limit.Tokens()
	tokenInByte := protocol.ByteCount(tokens / 8)
	return tokenInByte
}

// TimeUntilSend returns when the next packet should be sent.
// It returns zero if a packet can be sent immediately.
func (p *ratePacer) TimeUntilSend() monotime.Time {
	r := p.limit.ReserveN(time.Now(), int(p.maxDatagramSize*8))
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
	p.limit.SetLimit(rate.Limit(rateBits))
	burst := 8 * (float64(rateBits) / 200)
	p.limit.SetBurst(int(burst))
}
