package wasp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
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
	b := pkg.FIXED_CONNECT.Encode(body)
	conn.Write(b)
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

	callback.Callback.Subscribe = func(c context.Context, b []byte) {
		d := bytes.Split(b, []byte{'\n'})
		for _, v := range d {
			zap.L().Debug(string(v))
		}
	}
	Default().Run()
}

func TestWasp_subHandle(t *testing.T) {
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
	b := pkg.FIXED_CONNECT.Encode(body)
	conn.Write(b)
	time.Sleep(3 * time.Second)

	topic := "a/b\na/c\nb/b"
	conn.Write(pkg.FIXED_CONNECT.Encode([]byte(topic)))
	select {}

}

func TestWasp_pubHandle(t *testing.T) {
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
	b := pkg.FIXED_CONNECT.Encode(body)
	conn.Write(b)
	time.Sleep(1 * time.Second)
	topic := "a/b"
	conn.Write(pkg.FIXED_SUBSCRIBE.Encode([]byte(topic)))

	time.Sleep(1 * time.Second)

	connPub, err := net.Dial("tcp", "localhost:6000")
	if err != nil {
		t.Error(err)
		return
	}

	pb1 := &corepb.Connect{
		Udid:     uuid.New().String(),
		Group:    "123",
		Username: "123",
		Password: "123",
	}

	body1, err := proto.Marshal(pb1)
	if err != nil {
		t.Error(err)
		return
	}
	b1 := pkg.FIXED_CONNECT.Encode(body1)
	connPub.Write(b1)
	time.Sleep(1 * time.Second)
	resp, err := http.Get("http://img.mm4000.com/file/9/a3/e30335cd64_1044.jpg")
	if err != nil {
		zap.L().Error(err.Error())
		return
	}

	b2, err := io.ReadAll(resp.Body)
	if err != nil {
		zap.L().Error(err.Error())
		return
	}

	publish := &corepb.Publish{
		Topic: "a/b",
		Body:  b2,
	}

	pbody, _ := proto.Marshal(publish)
	for {
		connPub.Write(pkg.FIXED_PUBLISH.Encode(pbody))
		time.Sleep(10 * time.Millisecond)
	}
}
