package nfdump

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"testing"
)

func TestStreamReader(t *testing.T) {

	var data []byte
	var err error
	if data, err = ioutil.ReadFile("testdata/nfcapd-large-lzo"); err != nil {
		t.Error(err)
	}

	var reader = bytes.NewReader(data)

	var nfs *NFStream
	var record NFRecord
	nfs, err = StreamReader(reader)
	if err != nil {
		t.Errorf("StreamReader error:%#+v", err)
	}

	var x = 0
	for {
		if record, err = nfs.Row(); err == io.EOF {
			goto Stop
		} else if err != nil {
			t.Errorf("nfs.Row() error:%v", err)
			goto Stop
		}

		if x > 1 {
			break
		}
		if fmt.Sprintf("%#v", record) != fmt.Sprintf("%#v", testData[x]) {
			t.Errorf("test record:%d does not match", x)
			t.Log(fmt.Sprintf("%#v", record))
			t.Log(fmt.Sprintf("%#v", testData[x]))
		}
		x++
	}
Stop:
}
