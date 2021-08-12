package callback

import "github.com/gowasp/wasp/corepb"

type callback struct {
	// string: remote_addr.
	Connect func(string, *corepb.Connect) error
	Close   func(string) error
}

var (
	Callback = &callback{}
)
