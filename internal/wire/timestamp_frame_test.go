package wire

import (
	"bytes"
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestParseTimestampFrame(t *testing.T) {

	var data []byte
	// data = append(data, timestampFrameType)       // type
	data = append(data, encodeVarInt(1234567)...) // timestamp
	frame, l, err := parseTimestampFrame(data, protocol.Version1)

	require.NoError(t, err)

	require.Equal(t, frame.Timestamp, uint64(1234567))
	require.Equal(t, len(data), l)
}

func TestAppendAndParseTimestampFrame(t *testing.T) {
	f := TimestampFrame{Timestamp: uint64(424242)}

	data, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)

	expected := []byte{byte(FrameTypeTimestamp)}
	expected = append(expected, encodeVarInt(uint64(424242))...)
	require.Equal(t, data, expected)

	r := bytes.NewReader(data)
	typ, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.Equal(t, typ, uint64(FrameTypeTimestamp))
}
