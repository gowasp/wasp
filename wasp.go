package wasp

import (
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
	private     *pkg.Private

	gen Generater

	subMap *subMap
}

func Default() *Wasp {
	return &Wasp{
		readTimeout: readTimeout,
		subMap: &subMap{
			cache: make(map[string]map[string]*TCPConn),
		},
	}
}

func (w *Wasp) Run(addr ...string) error {
	var taddr string
	if len(addr) == 0 {
		taddr = ":6000"
	} else {
		taddr = addr[0]
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", taddr)
	if err != nil {
		return err
	}

	ln, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}

	zap.L().Info("Service started successfully", zap.String("listen", tcpAddr.String()))

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return err
		}

		go w.handle(&TCPConn{TCPConn: conn})
	}

}

func (w *Wasp) GenSeq(gen Generater) {
	w.gen = gen
}

func (w *Wasp) Private() *pkg.Private {
	if w.private == nil {
		w.private = &pkg.Private{}
	}
	return w.private
}

func (w *Wasp) handle(conn *TCPConn) {
	body := make([]byte, 4096)
	buf := &bytes.Buffer{}

	var (
		code byte

		size, varintLen int

		ctx = context.WithValue(context.Background(), _CTXPEER, &peer{})
	)
	for {

		// set timeout.
		err := conn.SetReadDeadline(time.Now().Add(w.readTimeout))
		if err != nil {
			return
		}

		n, err := conn.Read(body)
		if err != nil {
			conn.Close()
			if len(conn.SID()) == 0 {
				return
			}

			connMap.Delete(conn.SID())

			w.subMap.delete(conn.SID())

			if callback.Callback.Close != nil {
				callback.Callback.Close(conn.SID())
			}
			return
		}

		buf.Write(body[:n])

		for {
			if buf.Len() == 0 {
				break
			}
			if code == 0 {
				code = buf.Next(1)[0]
			}

			if code == byte(pkg.FIXED_PING) {
				w.typeHandle(ctx, conn, pkg.Fixed(code), nil)
				code = 0
				continue
			}

			size, varintLen = pkg.DecodeVarint(buf.Bytes()[0:])
			buf.Next(varintLen)

			if size+varintLen+1 == n {
				w.typeHandle(ctx, conn, pkg.Fixed(code), buf.Next(size))
				size, varintLen = 0, 0
				code = 0
				break
			}

			if size+varintLen+1 < n {
				w.typeHandle(ctx, conn, pkg.Fixed(code), buf.Next(size))
				code = 0
				continue
			}
			break

		}
	}
}

func (w *Wasp) typeHandle(ctx context.Context, conn *TCPConn, t pkg.Fixed, body []byte) {
	switch t {
	case pkg.FIXED_CONNECT:
		w.connect(ctx, conn, body)
	case pkg.FIXED_PING:
		if callback.Callback.Ping != nil {
			callback.Callback.Ping(conn.SID())
		}
	case pkg.FIXED_SUBSCRIBE:
		w.subHandle(ctx, conn, body)
	case pkg.FIXED_PUBLISH:
		w.pubHandle(ctx, conn, body)
	case pkg.FIXED_PVTPUBLISH:
		w.pvtPubHandle(ctx, conn, body)
	default:
		zap.L().Error("Unsupported PkgType " + fmt.Sprint(t))
	}
}

var (
	connMap sync.Map
)

func (w *Wasp) connect(ctx context.Context, conn *TCPConn, body []byte) {
	pb := &corepb.Connect{}
	if err := proto.Unmarshal(body, pb); err != nil {
		zap.L().Error(err.Error())
		return
	}

	if len(pb.GetUdid()) == 0 {
		zap.L().Error("udid is empty")
		conn.Close()
		return
	}

	if v, ok := connMap.Load(pb.GetUdid()); ok {
		oldConn := v.(*TCPConn)
		connMap.Delete(oldConn.SID())
		zap.L().Warn("Old connection will be closed", zap.String("sid", oldConn.SID()),
			zap.String("remote_addr", oldConn.RemoteAddr().String()),
		)
		oldConn.sid = ""
		oldConn.Close()
	}

	conn.sid = pb.GetUdid()

	if callback.Callback.Connect == nil {
		connMap.Store(conn.SID(), conn)
	} else {
		pr := ctx.Value(_CTXPEER).(*peer)
		pr.sid = conn.SID()
		pr.username = pb.Username
		pr.group = pb.Group
		pr.username = pb.Username

		err := callback.Callback.Connect(ctx, pb)
		if err != nil {
			conn.sid = ""
			return
		}

		connMap.Store(conn.SID(), conn)

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

	if _, err := conn.Write(pkg.FIXED_CONNECT.Encode(pbBody)); err != nil {
		conn.Close()
		zap.L().Warn(err.Error())
		return
	}

}

func (w *Wasp) subHandle(ctx context.Context, conn *TCPConn, body []byte) {
	w.subMap.put(string(body), conn.SID(), conn)

	if callback.Callback.Subscribe != nil {
		callback.Callback.Subscribe(ctx, string(body))
	}
}

var (
	ErrTopicNotFound = errors.New("topic not found")
)

func (w *Wasp) pubHandle(ctx context.Context, conn *TCPConn, body []byte) {
	topic := string(body[1 : 1+body[0]])

	ctx = context.WithValue(ctx, _CTXTOPIC, topic)
	seq, err := w.gen.Seq(ctx, body[1+body[0]:])
	if err != nil {
		return
	}

	if callback.Callback.PubData != nil {
		ctx = context.WithValue(ctx, _CTXSEQ, seq)
		ctx = context.WithValue(ctx, _CTXTOPIC, topic)
		go callback.Callback.PubData(ctx, body)
	}

	conns := w.subMap.gets(topic)
	if conns == nil {
		if callback.Callback.PubFail != nil {
			ctx = context.WithValue(ctx, _CTXSEQ, seq)
			ctx = context.WithValue(ctx, _CTXTOPIC, topic)
			callback.Callback.PubFail(ctx, body, err)
			zap.L().Warn(ErrTopicNotFound.Error() + topic)
		}
		return
	}

	idbody := append(pkg.EncodeVarint(seq), body...)

	for _, v := range conns {
		if _, err := v.Write(pkg.FIXED_PUBLISH.Encode(idbody)); err != nil {
			zap.L().Error(err.Error())
			if callback.Callback.PubFail != nil {
				ctx = context.WithValue(ctx, _CTXSEQ, seq)
				ctx = context.WithValue(ctx, _CTXTOPIC, topic)
				callback.Callback.PubFail(ctx, body, err)
			}
		}
	}
}

func (w *Wasp) pvtPubHandle(ctx context.Context, conn *TCPConn, body []byte) {
	seq, topicID, b := pkg.PvtPubDecode(body)

	if v := w.private.Get(topicID); v != nil {
		ctx = context.WithValue(ctx, _CTXSEQ, seq)
		ctx = context.WithValue(ctx, _CTXTOPIC, topicID)
		if err := v(ctx, b); err != nil {
			return
		}

		pvtPubAck := pkg.PvtPubAckEncode(seq)
		if _, err := conn.Write(pvtPubAck); err != nil && callback.Callback.PvtPubAckFail != nil {
			callback.Callback.PvtPubAckFail(seq, err)
		}

	} else {
		zap.S().Warnf("topicID %d was not found", topicID)
	}

}

type ctxString string

const (
	_CTXSEQ   ctxString = "ctxSeq"
	_CTXTOPIC ctxString = "ctxTopic"
	_CTXPEER  ctxString = "ctxPeer"
)

func CtxSeq(ctx context.Context) int {
	return ctx.Value(_CTXSEQ).(int)
}

func CtxPeer(ctx context.Context) *peer {
	return ctx.Value(_CTXPEER).(*peer)
}

func CtxTopic(ctx context.Context) string {
	return ctx.Value(_CTXTOPIC).(string)
}
