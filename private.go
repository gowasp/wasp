package wasp

import "sync"

type private struct {
	subMap sync.Map
}

type pvtSubFunc func(int, *TCPConn, []byte)

func (ps *private) Subscribe(topicID byte, f pvtSubFunc) {
	ps.subMap.Store(topicID, f)
}
