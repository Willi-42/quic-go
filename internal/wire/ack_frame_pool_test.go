package wire

import (
	"math/rand"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK Frame (for IETF QUIC)", func() {
	It("gets an ACK frame from the pool", func() {
		for i := 0; i < 100; i++ {
			ack := GetAckFrame()
			Expect(ack.AckRanges).To(BeEmpty())
			Expect(ack.ECNCE).To(BeZero())
			Expect(ack.ECT0).To(BeZero())
			Expect(ack.ECT1).To(BeZero())
			Expect(ack.DelayTime).To(BeZero())
			Expect(len(ack.TimeStamps)).To(BeZero())
			Expect(len(ack.TimeStampMapping)).To(BeZero())

			ack.AckRanges = make([]AckRange, rand.Intn(10))
			ack.ECNCE = 1
			ack.ECT0 = 2
			ack.ECT1 = 3
			ack.DelayTime = time.Hour
			ack.TimeStamps = append(ack.TimeStamps, 23423, 123, 42)
			ack.TimeStampMapping[42] = 37
			PutAckFrame(ack)
		}
	})
})
