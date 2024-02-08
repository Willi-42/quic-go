package wire

import "sync"

var ackFramePool = sync.Pool{New: func() any {
	return &AckFrame{}
}}

func GetAckFrame() *AckFrame {
	f := ackFramePool.Get().(*AckFrame)
	f.Reset()
	return f
}

func PutAckFrame(f *AckFrame) {
	if cap(f.AckRanges) > 4 {
		return
	}
	ackFramePool.Put(f)
}
