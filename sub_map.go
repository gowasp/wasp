package wasp

import (
	"sync"
)

type subMap struct {
	rwmutex sync.RWMutex
	cache   map[string]map[string]*TCPConn
}

func (s *subMap) put(topic, sid string, conn *TCPConn) {
	s.rwmutex.Lock()
	defer s.rwmutex.Unlock()

	if s.cache[topic] == nil {
		s.cache[topic] = make(map[string]*TCPConn)
	}

	s.cache[topic][sid] = conn
}

func (s *subMap) list(topic string) []*TCPConn {
	s.rwmutex.RLock()
	defer s.rwmutex.RUnlock()

	if s.cache[topic] == nil {
		return nil
	}

	conns := make([]*TCPConn, 0)
	for _, v := range s.cache[topic] {
		conns = append(conns, v)
	}

	return conns
}

func (s *subMap) delete(sid string) {
	s.rwmutex.Lock()
	defer s.rwmutex.Unlock()

	if s.cache == nil {
		return
	}

	for _, v := range s.cache {
		if v[sid] == nil {
			continue
		}

		delete(v, sid)

	}
}
