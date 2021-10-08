package callback

import (
	"context"

	"github.com/gowasp/corepb"
)

type callback struct {
	AfterListen func(string)
	// string: remote_addr.
	Connect   func(context.Context, *corepb.Connect) error
	Close     func(context.Context) error
	Ping      func(string)
	Subscribe func(context.Context, []string)
	PubData   func(context.Context, []byte)
	PubFail   func(context.Context, []byte, error)
	PubAck    func(context.Context, int)
}

var (
	Callback = &callback{}
)
