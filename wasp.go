package wasp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gowasp/corepb"
	"github.com/gowasp/pkg"
	"github.com/gowasp/wasp/callback"
	"go.uber.org/zap"
)

var (
	readTimeout = 5 * 60 * time.Second
)

func SetReadTimeout(t time.Duration) {
	readTimeout = t
}

type Generater interface {
	Seq(context.Context, []byte) (int, error)
}

type Wasp struct {
	readTimeout time.Duration

	bufferPool *sync.Pool

	connMap sync.Map
	subMap  *subMap
}

func Default() *Wasp {
	return &Wasp{
		readTimeout: readTimeout,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
		subMap: &subMap{
			cache: make(map[string]map[string]*TCPConn),
		},
	}
}

func (w *Wasp) Run(addr ...string) error {
	if len(addr) == 0 {
		addr = append(addr, ":6000")
	}

	taddr := addr[0]

	tcpAddr, err := net.ResolveTCPAddr("tcp", taddr)
	if err != nil {
		return err
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	if callback.Callback.AfterListen != nil {
		callback.Callback.AfterListen(addr[0])
	}

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return err
		}

		go w.handle(&TCPConn{TCPConn: conn})
	}

}

func (w *Wasp) handle(conn *TCPConn) {
	reader := bufio.NewReader(conn)
	buf := w.bufferPool.Get().(*bytes.Buffer)
	var (
		offset,
		varintLen,
		size int
		code byte

		ctx = context.WithValue(context.Background(), _CTXPEER, &peer{})
	)

	for {
		b, err := reader.ReadByte()
		if err != nil {
			conn.Close()
			if len(conn.SID()) == 0 {
				return
			}

			w.subMap.delete(conn.SID())
			w.connMap.Delete(conn.SID())

			if callback.Callback.Close != nil {
				callback.Callback.Close(ctx)
			}
		}

		if code == 0 {
			code = b
			continue
		}

		if code == byte(pkg.FIXED_PING) {
			w.heartbeat(conn)
			offset, varintLen, size, code = 0, 0, 0, 0
			continue
		}

		if varintLen == 0 {
			varintLen = int(b)
			continue
		}

		buf.WriteByte(b)
		offset++

		if offset == varintLen {
			px, pn := proto.DecodeVarint(buf.Next(offset))
			size = int(px) + pn
		}

		if offset == size && size != 0 {
			w.typeHandle(ctx, conn, pkg.Fixed(code), buf)
			offset, varintLen, size, code = 0, 0, 0, 0
			buf.Reset()
		}
	}
}

func (w *Wasp) typeHandle(ctx context.Context, conn *TCPConn, t pkg.Fixed, buf *bytes.Buffer) {
	switch t {
	case pkg.FIXED_CONNECT:
		w.connect(ctx, conn, buf)
	case pkg.FIXED_SUBSCRIBE:
		w.subHandle(ctx, conn, buf)
	case pkg.FIXED_PUBLISH:
		w.pubHandle(ctx, conn, buf)
	default:
		zap.L().Error("Unsupported PkgType " + fmt.Sprint(t))
	}
}

func (w *Wasp) connect(ctx context.Context, conn *TCPConn, buf *bytes.Buffer) {
	pb := &corepb.Connect{}
	if err := proto.Unmarshal(buf.Bytes(), pb); err != nil {
		zap.L().Error(err.Error())
		return
	}

	if len(pb.GetUdid()) == 0 {
		zap.L().Error("udid is empty")
		conn.Close()
		return
	}

	if v, ok := w.connMap.Load(pb.GetUdid()); ok {
		oldConn := v.(*TCPConn)
		w.connMap.Delete(oldConn.SID())
		w.subMap.delete(oldConn.SID())
		zap.L().Warn("old connection will be closed", zap.String("sid", oldConn.SID()),
			zap.String("remote_addr", oldConn.RemoteAddr().String()),
		)

		oldConn.sid = ""
		oldConn.Close()
	}

	conn.sid = pb.GetUdid()

	if callback.Callback.Connect == nil {
		w.connMap.Store(conn.SID(), conn)
	} else {
		pr := ctx.Value(_CTXPEER).(*peer)
		pr.sid = conn.SID()
		pr.username = pb.Username
		pr.group = pb.Group
		pr.remoteAddr = conn.RemoteAddr().String()

		err := callback.Callback.Connect(ctx, pb)
		if err != nil {
			conn.sid = ""
			conn.Close()
			return
		}

		w.connMap.Store(conn.SID(), conn)
	}

	pbAck := &corepb.ConnAck{
		Code: 0,
		Time: int32(time.Now().Unix()),
	}

	pbBody, err := proto.Marshal(pbAck)
	if err != nil {
		zap.L().Error(err.Error())
		return
	}

	if _, err := conn.Write(pkg.ConnAckEncode(pbBody)); err != nil {
		conn.Close()
		zap.L().Warn(err.Error())
		return
	}

}

func (w *Wasp) subHandle(ctx context.Context, conn *TCPConn, buf *bytes.Buffer) {
	if buf.Len() == 0 {
		return
	}

	ts := bytes.Split(buf.Bytes(), []byte{'\n'})
	for _, v := range ts {
		if len(v) != 0 {
			w.subMap.put(string(v), conn.SID(), conn)
		}
	}

	if callback.Callback.Subscribe != nil {
		callback.Callback.Subscribe(ctx, buf.Bytes())
	}
}

var (
	ErrSubscriberNotFound = errors.New("subscriber not found")
)

// for test
//var i int

func (w *Wasp) pubHandle(ctx context.Context, conn *TCPConn, buf *bytes.Buffer) {
	topicLen := buf.Next(1)[0]
	topic := string(buf.Next(int(topicLen)))

	conns := w.subMap.list(topic)
	if conns == nil {
		zap.L().Warn("no subscribers")
		return
	}

	// for test
	//i++
	//os.WriteFile("./"+fmt.Sprint(i)+".jpeg", buf.Bytes(), os.ModePerm)

	for _, v := range conns {
		if _, err := v.Write(buf.Bytes()); err != nil {
			zap.L().Warn(err.Error())
		}
	}
}

func (w *Wasp) heartbeat(conn *TCPConn) {
	conn.Write([]byte{byte(pkg.FIXED_PONG)})
}

func (w *Wasp) SubConns(topic string) []*TCPConn {
	return w.subMap.list(topic)
}

type ctxString string

const (
	_CTXTOPIC      ctxString = "ctxTopic"
	_CTXPEER       ctxString = "ctxPeer"
	_CTXSUBSCRIBER ctxString = "ctxSubscriber"
)

func CtxPeer(ctx context.Context) *peer {
	return ctx.Value(_CTXPEER).(*peer)
}

func CtxTopic(ctx context.Context) string {
	return ctx.Value(_CTXTOPIC).(string)
}

func CtxSubscriber(ctx context.Context) string {
	suber := ctx.Value(_CTXSUBSCRIBER)
	if suber == nil {
		return ""
	} else {
		return suber.(string)
	}
}
