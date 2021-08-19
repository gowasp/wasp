package callback

import (
	"context"

	"github.com/gowasp/corepb"
)

type callback struct {
	// string: remote_addr.
	Connect   func(context.Context, *corepb.Connect) error
	Close     func(string) error
	Ping      func(string)
	Subscribe func(context.Context, []byte)
	PubData   func(context.Context, []byte)
	PubFail   func(context.Context, []byte, error)
	PubAck    func(context.Context, int)
}

var (
	Callback = &callback{}
)
