package wasp

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"github.com/gowasp/corepb"
	"github.com/gowasp/pkg"
	"github.com/gowasp/wasp/callback"
	"go.uber.org/zap"
)

func TestWasp_connect(t *testing.T) {
	var a pkg.Fixed = 1
	aa := fmt.Sprint(a)
	println(aa)
	go Default().Run()
	time.Sleep(1 * time.Second)
	conn, err := net.Dial("tcp", "localhost:6000")
	if err != nil {
		t.Error(err)
		return
	}

	pb := &corepb.Connect{
		Udid:     uuid.New().String(),
		Group:    "123",
		Username: "123",
		Password: "123",
	}

	body, err := proto.Marshal(pb)
	if err != nil {
		t.Error(err)
		return
	}
	conn.Write(pkg.FIXED_CONNECT.Encode(body))
	select {}
}

func TestWasp_Run(t *testing.T) {
	l, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(l)
	Default().Run()
}

func TestWasp_Publish(t *testing.T) {
	l, _ := zap.NewDevelopment()
	zap.ReplaceGlobals(l)

	callback.Callback.Ping = func(s string) {
		zap.L().Debug(s)
	}

	callback.Callback.Subscribe = func(c context.Context, s string) {
		zap.L().Debug(s)
	}
	Default().Run()
}
