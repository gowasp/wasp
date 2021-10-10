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
	var (
		ctx = context.WithValue(context.Background(), _CTXPEER, &peer{})
	)

	for {
		var (
			offset,
			varintLen,
			size int
			code byte
		)

		buf := w.bufferPool.Get().(*bytes.Buffer)
		buf.Reset()

		conn.SetReadDeadline(time.Now().Add(w.readTimeout))

		for {
			b, err := reader.ReadByte()
			if err != nil {
				w.bufferPool.Put(buf)

				zap.L().Warn(conn.SID() + ": " + err.Error())
				conn.Close()

				if conn.SID() == "" {
					return
				}

				mapConn, ok := w.connMap.Load(conn.SID())
				if !ok {
					return
				}

				if conn.connectTime < mapConn.(*TCPConn).connectTime {
					return
				} else {
					w.connMap.Delete(conn.SID())
				}

				if callback.Callback.Close != nil {
					callback.Callback.Close(ctx)
				}
				return
			}

			buf.WriteByte(b)
			offset++

			if code == 0 {
				code = b
				if pkg.Fixed(code) == pkg.FIXED_PING {
					w.heartbeat(conn)
					w.bufferPool.Put(buf)
					break
				}
				continue
			}
			if varintLen == 0 {
				px, pn := pkg.DecodeVarint(buf.Bytes()[1:])
				size = int(px) + pn
				if size != 0 {
					varintLen = pn
				}
				continue
			}

			if offset == size+1 && size != 0 {
				w.typeHandle(ctx, conn, pkg.Fixed(code), varintLen, buf)
				w.bufferPool.Put(buf)
				break
			}

		}
	}

}

func (w *Wasp) typeHandle(ctx context.Context, conn *TCPConn, t pkg.Fixed, varintLen int, buf *bytes.Buffer) {
	switch t {
	case pkg.FIXED_CONNECT:
		w.connect(ctx, conn, varintLen, buf)
	case pkg.FIXED_SUBSCRIBE:
		w.subHandle(ctx, conn, varintLen, buf)
	case pkg.FIXED_PUBLISH:
		w.pubHandle(ctx, conn, varintLen, buf)
	default:
		zap.S().Errorf("Unsupported PkgType: %s, sid: %s, remote_addr: %s", fmt.Sprint(t), conn.SID(), conn.RemoteAddr().String())
	}
}

func (w *Wasp) connect(ctx context.Context, conn *TCPConn, varintLen int, buf *bytes.Buffer) {
	pb := &corepb.Connect{}
	if err := proto.Unmarshal(buf.Bytes()[1+varintLen:], pb); err != nil {
		zap.L().Error(err.Error())
		return
	}

	if len(pb.GetUdid()) == 0 {
		zap.L().Error("udid is empty")
		conn.Close()
		return
	}

	if _, ok := w.connMap.Load(pb.GetUdid()); ok {
		w.connMap.Delete(pb.GetUdid())
		zap.L().Warn("old connection will be closed")
	}

	conn.sid = pb.GetUdid()
	conn.connectTime = time.Now().UnixNano() / 1e6

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

	if _, err := conn.Write(pkg.FIXED_CONNACK.Encode(pbBody)); err != nil {
		conn.Close()
		zap.L().Warn(err.Error())
		return
	}

}

func (w *Wasp) subHandle(ctx context.Context, conn *TCPConn, varintLen int, buf *bytes.Buffer) {
	ts := bytes.Split(buf.Bytes()[1+varintLen:], []byte{'\n'})
	strTopics := make([]string, 0)
	for _, v := range ts {
		if len(v) != 0 {
			w.subMap.put(string(v), conn.SID(), conn)
			strTopics = append(strTopics, string(v))
		}
	}

	if callback.Callback.Subscribe != nil {
		callback.Callback.Subscribe(ctx, strTopics)
	}
}

var (
	ErrSubscriberNotFound = errors.New("subscriber not found")
)

func (w *Wasp) pubHandle(ctx context.Context, conn *TCPConn, varintLen int, buf *bytes.Buffer) {
	tl := buf.Bytes()[1+varintLen]
	topic := string(buf.Bytes()[2+varintLen : 2+varintLen+int(tl)])
	conns := w.subMap.list(string(topic))
	if conns == nil {
		zap.L().Warn("no subscribers")
		return
	}

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
