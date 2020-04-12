package nfdump

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"testing"
)

var testData = []NFRecord{
	NFRecord{Flags: 0x86, MsecFirst: 0x3be, MsecLast: 0x3be, First: 0x5d51b507, Last: 0x5d51b507, FwdStatus: 0x0, TCPFlags: 0x10, Proto: 0x6, Tos: 0x0, SrcPort: 0x1bb, DstPort: 0xa16a, ExporterSysID: 0x4c8, Reserved: 0x0, SrcIP: net.IP{0xd8, 0xce, 0x91, 0x83}, DstIP: net.IP{0xd1, 0x94, 0xcd, 0x37}, PacketCount: 0xbb8, ByteCount: 0x44aa20, Input: 0x492, Output: 0x4f0, SrcAS: 0xd1, DstAS: 0x32c, DstTos: 0x0, Dir: 0x0, SrcMask: 0xf, DstMask: 0x14, NextHopIP: net.IP{0x40, 0x56, 0x4f, 0x7f}, BGPNextIP: net.IP(nil), SrcVlan: 0x2, DstVLan: 0x0, OutPkts: 0x0, OutBytes: 0x0, AggeFlows: 0x0, RouterIP: net.IP{0x42, 0x6e, 0x1, 0x11}, Received: 0x16c872c34c8},
	NFRecord{Flags: 0x86, MsecFirst: 0x2a, MsecLast: 0x2a, First: 0x5d51b508, Last: 0x5d51b508, FwdStatus: 0x0, TCPFlags: 0x10, Proto: 0x6, Tos: 0x0, SrcPort: 0x291d, DstPort: 0x1bb, ExporterSysID: 0x4c8, Reserved: 0x0, SrcIP: net.IP{0xc8, 0x44, 0x96, 0x56}, DstIP: net.IP{0x63, 0x56, 0x3d, 0xaa}, PacketCount: 0xbb8, ByteCount: 0x26160, Input: 0x492, Output: 0x3e7, SrcAS: 0x6ef3, DstAS: 0x407d, DstTos: 0x0, Dir: 0x0, SrcMask: 0x18, DstMask: 0x16, NextHopIP: net.IP{0x40, 0x56, 0x4f, 0x7b}, BGPNextIP: net.IP(nil), SrcVlan: 0x2, DstVLan: 0x0, OutPkts: 0x0, OutBytes: 0x0, AggeFlows: 0x0, RouterIP: net.IP{0x42, 0x6e, 0x1, 0x11}, Received: 0x16c872c34c8},
}

var testFileRecordLength = 100000

var testFiles = []string{
	"testdata/nfcapd-large-none",
	"testdata/nfcapd-large-lzo",
	// "testdata/nfcapd-large-lz4", //Not currently supported
	// "testdata/nfcapd-large-bz2", //Not currently supported
}

func TestReader(t *testing.T) {

	var data []byte
	var err error
	if data, err = ioutil.ReadFile("testdata/nfcapd-large-lzo"); err != nil {
		t.Error(err)
	}

	var reader = bytes.NewReader(data)
	var nff *NFFile

	if nff, err = ParseReader(reader); err != nil {
		t.Error(err)
	}

	for x, record := range nff.Records {
		//Only test first 2 records
		if x > 1 {
			break
		}
		if fmt.Sprintf("%#v", record) != fmt.Sprintf("%#v", testData[x]) {
			t.Errorf("test record:%d does not match", x)
		}
	}

	if len(nff.Records) != 100000 {
		t.Errorf("Unexpected record count:%d in test file, expected 10", len(nff.Records))
	}

}

//BenchmarkReadFile read all test files to allow benchmarking how fast files can be read.
func BenchmarkReadFile(b *testing.B) {

	for n := 0; n < b.N; n++ {
		var err error
		var data []byte
		var nff *NFFile

		if data, err = ioutil.ReadFile(testFiles[0]); err != nil {
			b.Error(err)
		}

		var reader = bytes.NewReader(data)

		if nff, err = ParseReader(reader); err != nil {
			b.Error(err)
		}

		if len(nff.Records) != testFileRecordLength {
			b.Error("Unexpected Record count")
		}
	}
}
