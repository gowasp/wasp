package pkg

import (
	"testing"
	"time"
)

func TestPkgType_PvtDecode(t *testing.T) {
	body := append(EncodeVarint(int(time.Now().Unix())), byte(10))
	ebody := append(EncodeVarint(len(body)), body...)
	pvt := append([]byte{byte(PUBLISH)}, ebody...)
	dt, topicID, r := PUBLISH.PvtDecode(pvt[1:])
	t.Log(dt, "-", topicID, "-", r)
}
