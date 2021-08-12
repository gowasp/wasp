package pkg

import (
	"encoding/binary"
	"errors"
)

type PkgType byte

const (
	CONNECT PkgType = iota + 1
	CONNACK
	PING
	PONG
	PUBLISH
	PUBACK
	SUBSCRIBE
	SUBACK
	UNSUBSCRIBE
	UNSUBACK
	PVTSUBSCRIBE
	PVTPUBLISH
	PVTPUBACK
	FORWARD
)

var (
	ErrVarintOutOfRange = errors.New("varint out of range")
)

func EncodeVarint(x int) []byte {
	var buf [5]byte
	var n int
	for n = 0; x > 127; n++ {
		buf[n] = 0x80 | uint8(x&0x7F)
		x >>= 7
	}

	if n > 4 {
		return nil
	}
	buf[n] = uint8(x)
	n++
	return buf[0:n]
}

func DecodeVarint(b []byte) (int, int) {
	u, i := binary.Uvarint(b)
	return int(u), i
}

func (pt PkgType) Encode(body []byte) []byte {
	ebody := append(EncodeVarint(len(body)), body...)
	cbody := append([]byte{byte(pt)}, ebody...)
	return cbody
}

// int: datetime.
// byte: topicID.
// []byte: remaining content.
func (pt PkgType) PvtDecode(body []byte) (int, byte, []byte) {
	v, n := DecodeVarint(body)
	return v, body[n], body[v-n-1:]
}
