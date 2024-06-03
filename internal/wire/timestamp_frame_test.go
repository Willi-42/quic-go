package wire

import (
	"bytes"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/quicvarint"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Timestamp Frame", func() {
	Context("parsing", func() {
		It("parses a timestamp frame", func() {
			var data []byte
			// data = append(data, timestampFrameType)       // type
			data = append(data, encodeVarInt(1234567)...) // timestamp
			b := bytes.NewReader(data)
			frame, err := parseTimestampFrame(b, protocol.Version1)
			Expect(err).To(Succeed())
			Expect(frame.Timestamp).To(Equal(uint64(1234567)))
			Expect(b.Len()).To(BeZero())
		})

		It("append and parses a timestamp frame", func() {
			f := TimestampFrame{Timestamp: uint64(424242)}

			data, err := f.Append(nil, protocol.Version1)
			Expect(err).ToNot(HaveOccurred())

			r := bytes.NewReader(data)
			typ, err := quicvarint.Read(r) // remove type field
			Expect(err).ToNot(HaveOccurred())
			Expect(typ).To(Equal(uint64(timestampFrameType)))

			frame, err := parseTimestampFrame(r, protocol.Version1)
			Expect(err).To(Succeed())
			Expect(frame.Timestamp).To(Equal(uint64(424242)))
			Expect(r.Len()).To(BeZero())
		})
	})
})
