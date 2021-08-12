package wasp

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/gowasp/wasp/callback"
	"github.com/gowasp/wasp/corepb"
	"github.com/gowasp/wasp/pkg"
	"go.uber.org/zap"
)

var (
	readTimeout = 5 * 60 * time.Second
)

func SetReadTimeout(t time.Duration) {
	readTimeout = t
}

type Wasp struct {
	readTimeout time.Duration
	private     *private
}

func Default() *Wasp {
	return &Wasp{
		readTimeout: readTimeout,
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

func (w *Wasp) handle(conn *TCPConn) {
	body := make([]byte, 4096)
	buf := &bytes.Buffer{}

	var (
		code byte

		offset, size, varintLen int
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
			if len(conn.SID()) != 0 && callback.Callback.Close != nil {
				callback.Callback.Close(conn.SID())
			}
			return
		}

		buf.Write(body[:n])

		if offset == 0 {
			code = buf.Bytes()[0]
			size, varintLen = pkg.DecodeVarint(buf.Bytes()[1:])
			offset = n - 1 - varintLen
			buf.Next(1 + varintLen)

			if size+varintLen+1 <= n {
				w.pkgHandle(pkg.PkgType(code), conn, buf.Next(size))
				buf.Reset()
				offset, size, varintLen = 0, 0, 0
				code = 0
			}
			continue
		}

		offset += n

		if offset < size {
			continue
		} else if offset == size {
			w.pkgHandle(pkg.PkgType(code), conn, buf.Next(size))
			buf.Reset()
			offset, size, varintLen = 0, 0, 0
			code = 0
		} else {
			w.pkgHandle(pkg.PkgType(code), conn, buf.Next(size))
			offset, size, varintLen = 0, 0, 0
			code = 0
		}
	}
}

func (w *Wasp) pkgHandle(pt pkg.PkgType, conn *TCPConn, body []byte) {
	switch pt {
	case pkg.CONNECT:
		w.connect(conn, body)
	case pkg.PVTPUBACK:
		w.pvtPubAckHandle(conn, body)
	default:
		zap.L().Error("Unsupported PkgType " + fmt.Sprint(pt))
	}
}

var (
	connMap sync.Map
)

func (w *Wasp) connect(conn *TCPConn, body []byte) {
	pb := &corepb.Connect{}
	if err := proto.Unmarshal(body, pb); err != nil {
		zap.L().Error(err.Error())
		return
	}

	if pb.GetUdid() == "" || pb.GetPassword() == "" || pb.GetUsername() == "" {
		zap.L().Error("Security parameter is empty")
		conn.Close()
		return
	}

	if v, ok := connMap.Load(pb.GetUdid()); ok {
		oldConn := v.(*TCPConn)
		connMap.Delete(oldConn.SID())
		zap.L().Warn("Old connection will be closed", zap.String("sid", oldConn.SID()),
			zap.String("remote_addr", oldConn.RemoteAddr().String()),
		)
		oldConn.SetSID("")
		oldConn.Close()
	}

	conn.SetSID(pb.GetUdid())

	if callback.Callback.Connect == nil {
		connMap.Store(conn.SID(), conn)
		return
	}

	err := callback.Callback.Connect(conn.RemoteAddr().String(), pb)
	if err != nil {
		conn.SetSID("")
		return
	}

	connMap.Store(conn.SID(), conn)

	pbAck := &corepb.ConnAck{
		Code:     0,
		Datetime: int32(time.Now().Unix()),
	}

	pbBody, err := proto.Marshal(pbAck)
	if err != nil {
		zap.L().Error(err.Error())
		return
	}

	if _, err := conn.Write(pkg.CONNACK.Encode(pbBody)); err != nil {
		conn.Close()
		zap.L().Warn(err.Error())
		return
	}

}

func (w *Wasp) pvtPubAckHandle(conn *TCPConn, body []byte) {
	t, topicID, b := pkg.PVTPUBACK.PvtDecode(body)
	if v, ok := w.private.subMap.Load(topicID); ok {
		v.(pvtSubFunc)(t, conn, b)
	} else {
		zap.S().Warnf("topicID %d was not found", topicID)
	}
}

func (w *Wasp) Private() *private {
	if w.private == nil {
		w.private = &private{}
	}
	return w.private
}
