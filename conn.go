package wasp

import (
	"net"
)

type TCPConn struct {
	*net.TCPConn
	// SID session id.
	sid string
}

func (c *TCPConn) SID() string {
	return c.sid
}

func (c *TCPConn) Write(b []byte) (int, error) {
	return c.TCPConn.Write(b)
}
