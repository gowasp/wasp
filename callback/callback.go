package callback

import "github.com/gowasp/corepb"

type callback struct {
	// string: remote_addr.
	Connect func(string, *corepb.Connect) error
	Close   func(string) error
	Pong    func(string)
}

var (
	Callback = &callback{}
)
