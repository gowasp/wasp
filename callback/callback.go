package callback

import (
	"context"

	"github.com/gowasp/corepb"
)

type callback struct {
	// string: remote_addr.
	Connect func(string, *corepb.Connect) error
	Close   func(string) error
	Pong    func(string)

	PvtPubAckFail func(int, error)

	Subscribe func(context.Context, string)
	PubData   func(context.Context, []byte)
	PubFail   func(context.Context, error, []byte)
}

var (
	Callback = &callback{}
)
