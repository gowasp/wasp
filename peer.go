package wasp

type peer struct {
	sid             string
	username, group string
	remoteAddr      string
}

func (p *peer) UDID() string {
	return p.sid
}

func (p *peer) Group() string {
	return p.group
}

func (p *peer) Username() string {
	return p.username
}

func (p *peer) RemoteAddr() string {
	return p.remoteAddr
}
