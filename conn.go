package wasp

import (
	"net"
)

type TCPConn struct {
	*net.TCPConn
	// SID session id.
	sid                       string
	username, group, password string
}

func (c *TCPConn) SID() string {
	return c.sid
}

func (c *TCPConn) SetSID(sid string) {
	c.sid = sid
}

func (c *TCPConn) Group() string {
	return c.group
}

func (c *TCPConn) Username() string {
	return c.username
}

func (c *TCPConn) Password() string {
	return c.password
}

func (c *TCPConn) Write(b []byte) (int, error) {
	return c.TCPConn.Write(b)
}
