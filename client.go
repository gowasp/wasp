package wasp

// type Client struct { // for dial.
// 	wasp    *Wasp
// 	tcpConn *core.TCPConn
// 	udpConn *core.UDPConn

// 	ConnectFunc func() []byte
// }

// func NewClient() *Client {
// 	return &Client{
// 		wasp: &Wasp{
// 			option: &Option{
// 				ReadTimeout:  5 * 60 * time.Second,
// 				WriteTimeOut: 5 * time.Second,
// 			}},
// 	}
// }

// func (c *Client) SetOption(opt *Option) {
// 	c.wasp.option = opt
// }

// func (c *Client) Interfacer(ti core.Interface) *Client {
// 	c.wasp.handler, c.wasp.closer = ti, ti
// 	return c
// }

// func (c *Client) Handler(handler core.Handler) *Client {
// 	c.wasp.handler = handler
// 	return c
// }

// func (c *Client) Closer(closer core.Closer) *Client {
// 	c.wasp.closer = closer
// 	return c
// }

// func (c *Client) Dial(network, addr string) error {
// 	switch network {
// 	case "tcp", "tcp4", "tcp6":
// 		return c.dialTCP(network, addr)
// 	case "udp", "udp4", "udp6":
// 		return c.dialUDP(network, addr)
// 	default:
// 		panic("Unsupported network " + network)
// 	}
// }

// func (c *Client) dialTCP(network, addr string) error {
// 	conn, err := net.Dial(network, addr)
// 	if err != nil {
// 		return err
// 	}

// 	c.tcpConn = &core.TCPConn{TCPConn: conn.(*net.TCPConn)}

// 	if c.ConnectFunc != nil {
// 		if _, err := c.tcpConn.Write(c.ConnectFunc()); err != nil {
// 			return err
// 		}
// 	}

// 	if err := c.wasp.readTCP(c.tcpConn); err != nil {
// 		return err
// 	}

// 	return nil
// }

// func (c *Client) dialUDP(network, addr string) error {
// 	conn, err := net.Dial(network, addr)
// 	if err != nil {
// 		return err
// 	}

// 	c.udpConn = &core.UDPConn{UDPConn: conn.(*net.UDPConn)}

// 	if c.ConnectFunc != nil {
// 		if _, err := c.udpConn.Write(c.ConnectFunc()); err != nil {
// 			return err
// 		}
// 	}

// 	if err := c.wasp.readUDP(c.udpConn); err != nil {
// 		return err
// 	}
// 	return nil
// }
