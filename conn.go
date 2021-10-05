package wasp

import (
	"net"
)

type TCPConn struct {
	*net.TCPConn
	// SID session id.
	sid string
	// client connection time.
	connectTime int64
}

func (c *TCPConn) SID() string {
	return c.sid
}

func (c *TCPConn) ConnectTime() int64 {
	return c.connectTime
}

func (c *TCPConn) Write(b []byte) (int, error) {
	return c.TCPConn.Write(b)
}
