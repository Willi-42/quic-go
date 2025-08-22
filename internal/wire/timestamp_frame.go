package wire

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// An TimestampFrame is a timestamp frame
type TimestampFrame struct {
	Timestamp uint64
}

// parseTimestampFrame reads a timestamp frame
func parseTimestampFrame(b []byte, _ protocol.Version) (*TimestampFrame, int, error) {
	frame := &TimestampFrame{}

	// read the timestamp
	ts, l, err := quicvarint.Parse(b)
	if err != nil {
		return nil, l, err
	}
	frame.Timestamp = ts

	return frame, l, nil
}

// Append appends an timestamp frame.
func (f *TimestampFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = quicvarint.Append(b, uint64(FrameTypeTimestamp))
	b = quicvarint.Append(b, f.Timestamp)

	return b, nil
}

// Length of a written frame
func (f *TimestampFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := 1 + quicvarint.Len(f.Timestamp)

	return protocol.ByteCount(length)
}
