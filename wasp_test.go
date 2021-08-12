package wasp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/uuid"
	"github.com/gowasp/corepb"
	"github.com/gowasp/pact"
	"github.com/gowasp/wasp/callback"
)

// type Test struct{}

// func (te *Test) Handle(conn core.Conn, b []byte) {
// 	log.Println(string(b))
// }

// type BigData struct{}

// func (bd *BigData) Handle(conn core.Conn, b []byte) {
// 	t := time.Now().UnixNano()
// 	os.WriteFile("./"+fmt.Sprint(t)+".jpeg", b, os.ModePerm)
// 	log.Println(len(b))
// }

// func TestWasp_readTCP(t *testing.T) {
// 	go New().Handler(&Test{}).Listen("tcp", ":8080")
// 	time.Sleep(1 * time.Second)
// 	conn, err := net.Dial("tcp", "localhost:8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}
// 	b := core.TCPEncode([]byte("wasp"))
// 	go conn.Write(b)

// 	select {}
// }

// func TestWasp_readTCP_Clients(t *testing.T) {
// 	go New().Handler(&Test{}).Listen("tcp", ":8080")
// 	time.Sleep(1 * time.Second)
// 	conn, err := net.Dial("tcp", "localhost:8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}
// 	conn1, err := net.Dial("tcp", "localhost:8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}
// 	b := core.TCPEncode([]byte("wasp"))
// 	go conn.Write(b)
// 	go conn.Write(b)
// 	go conn.Write(b)

// 	conn1.Write(b)
// 	go conn1.Write(b)
// 	go conn1.Write(b)
// 	select {}
// }

// func TestWasp_readTCP_BigData(t *testing.T) {
// 	go New().Handler(&BigData{}).Listen("tcp", ":8080")
// 	time.Sleep(1 * time.Second)
// 	conn, err := net.Dial("tcp", "localhost:8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	resp, err := http.Get("http://img.mm4000.com/file/9/a3/e30335cd64_1044.jpg")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	defer resp.Body.Close()

// 	ib, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}
// 	b := core.TCPEncode(ib)
// 	go conn.Write(b)

// 	select {}
// }

// func TestWasp_readUDP_Clients(t *testing.T) {
// 	New().Handler(&Test{}).Listen("udp", ":8080")
// 	time.Sleep(1 * time.Second)
// 	conn, err := net.Dial("udp", "0.0.0.0:8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}
// 	conn1, err := net.Dial("udp", "localhost:8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}
// 	bs := core.UDPEncode([]byte("wasp"))
// 	go func() {
// 		for i := 0; i < 100; i++ {
// 			for i, v := range bs {
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn.Write(seq)
// 			}

// 		}
// 	}()

// 	bs1 := core.UDPEncode([]byte("wasp2"))
// 	go func() {
// 		for i := 0; i < 100; i++ {
// 			for i, v := range bs1 {
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs1)-i))

// 				seq = append(seq, v...)
// 				conn1.Write(seq)
// 			}

// 		}
// 	}()
// 	select {}
// }

// func TestWasp_readUDP(t *testing.T) {
// 	go New().Handler(&Test{}).Listen("udp", ":8080")
// 	time.Sleep(1 * time.Second)
// 	conn, err := net.Dial("udp", "0.0.0.0:8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	bs := core.UDPEncode([]byte("wasp"))

// 	go func() {
// 		for i := 0; i < 100; i++ {
// 			for i, v := range bs {
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn.Write(seq)
// 			}

// 		}
// 	}()
// 	select {}
// }

// func TestWasp_readUDP_Clients_BigData(t *testing.T) {
// 	go New().Handler(&BigData{}).Listen("udp", ":8080")
// 	time.Sleep(1 * time.Second)
// 	udpAddr, _ := net.ResolveUDPAddr("udp", ":8080")
// 	conn, err := net.DialUDP("udp", nil, udpAddr)
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	conn1, err := net.DialUDP("udp", nil, udpAddr)
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	conn2, err := net.Dial("udp", ":8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	conn3, err := net.Dial("udp", ":8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	conn4, err := net.Dial("udp", ":8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	conn5, err := net.Dial("udp", ":8080")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	resp, err := http.Get("http://img.mm4000.com/file/9/a3/e30335cd64_1044.jpg")
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	defer resp.Body.Close()

// 	ib, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		t.Error(err)
// 		return
// 	}

// 	bs := core.UDPEncode(ib)

// 	go func() {
// 		for j := 0; j < 10; j++ {
// 			for i, v := range bs {
// 				time.Sleep(20 * time.Microsecond)
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn.Write(seq)
// 			}
// 		}
// 	}()

// 	go func() {
// 		for j := 0; j < 10; j++ {
// 			for i, v := range bs {
// 				time.Sleep(20 * time.Microsecond)
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn1.Write(seq)
// 			}
// 		}
// 	}()

// 	go func() {
// 		for j := 0; j < 10; j++ {
// 			for i, v := range bs {
// 				time.Sleep(20 * time.Microsecond)
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn2.Write(seq)
// 			}
// 		}
// 	}()

// 	go func() {
// 		for j := 0; j < 10; j++ {
// 			for i, v := range bs {
// 				time.Sleep(20 * time.Microsecond)
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn3.Write(seq)
// 			}
// 		}
// 	}()

// 	go func() {
// 		for j := 0; j < 10; j++ {
// 			for i, v := range bs {
// 				time.Sleep(20 * time.Microsecond)
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn4.Write(seq)
// 			}
// 		}
// 	}()

// 	go func() {
// 		for j := 0; j < 10; j++ {
// 			for i, v := range bs {
// 				time.Sleep(20 * time.Microsecond)
// 				seq := make([]byte, 2)
// 				binary.BigEndian.PutUint16(seq, uint16(len(bs)-i))

// 				seq = append(seq, v...)
// 				conn5.Write(seq)
// 			}
// 		}
// 	}()
// 	select {}
// }

// func TestClient_Write(t *testing.T) {
// 	go New().Handler(&Test{}).Listen("tcp", ":8080")
// 	time.Sleep(1 * time.Second)

// 	c := NewClient()
// 	go c.Dial("tcp", ":8080")
// 	time.Sleep(1 * time.Second)

// 	if _, err := c.tcpConn.Write([]byte("wasp")); err != nil {
// 		t.Error(err.Error())
// 	}
// 	select {}
// }

// func TestClient_dialUDP(t *testing.T) {
// 	go New().Handler(&Test{}).Listen("udp", ":8080")
// 	time.Sleep(1 * time.Second)

// 	c := NewClient()
// 	go func() {
// 		if err := c.Dial("udp", "localhost:8080"); err != nil {
// 			t.Error(err.Error())
// 		}
// 	}()
// 	time.Sleep(2 * time.Second)

// 	if _, err := c.udpConn.Write([]byte("wasp")); err != nil {
// 		t.Error(err.Error())
// 	}

// 	select {}
// }

func TestWasp_connect(t *testing.T) {
	var a pact.Type = 1
	aa := fmt.Sprint(a)
	println(aa)
	callback.Callback.Connect = func(s string, c *corepb.Connect) error {
		t.Logf("%s\n", s)
		t.Logf("%+v\n", c)
		return nil
	}
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
	conn.Write(pact.CONNECT.Encode(body))
	select {}
}

func TestWasp_Private(t *testing.T) {
	w := Default()
	w.Private()
}
