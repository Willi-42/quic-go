package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
)

// An TimestampFrame is a timestamp frame
type TimestampFrame struct {
	Timestamp uint64
}

// parseTimestampFrame reads a timestamp frame
func parseTimestampFrame(r *bytes.Reader, _ protocol.Version) (*TimestampFrame, error) {
	frame := &TimestampFrame{}

	// read the timestamp
	ts, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	frame.Timestamp = ts

	return frame, nil
}

// Append appends an timestamp frame.
func (f *TimestampFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, timestampFrameType)
	b = quicvarint.Append(b, f.Timestamp)

	return b, nil
}

// Length of a written frame
func (f *TimestampFrame) Length(_ protocol.Version) protocol.ByteCount {
	length := 1 + quicvarint.Len(f.Timestamp)

	return protocol.ByteCount(length)
}
