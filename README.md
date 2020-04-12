# nfdump
NFDump File Reader

This library allows Go programs to read file produced by nfdump.

https://github.com/phaag/nfdump
> nfdump is a toolset in order to collect and process netflow and sflow data, sent from netflow/sflow compatible devices. The toolset supports netflow v1, v5/v7,v9,IPFIX and SFLOW. nfdump supports IPv4 as well as IPv6.


## ParseReader Example
Read whole file and return struct with all meta data and records.

```go

package main

import (
	"bufio"
	"log"
	"os"
	"time"

	"github.com/chrispassas/nfdump"

)

func main() {
    var filePath = "testdata/nfcapd-small-lzo"
    var nff *nfdump.NFFile
	  var err error
    var f *os.File
	  
    f, err = os.Open(filePath)
	  
    if err != nil {
		    log.Fatalf("[ERROR] os.Open error:%#+v", err)
	  }
	  defer f.Close()
    
    var reader = bufio.NewReader(f)
	  nff, err = nfdump.ParseReader(reader)
	  
    if err != nil {
		    log.Fatalf("[ERROR] nfdump.ParseReader error:%#+v", err)
	  }
    
    for _, record := range nff.Records {
        log.Printf("Received:%s routerIP:%s srcIP:%s dstIP:%s srcPort:%d dstPort:%d srcMask:%d dstMask:%d ipNextHop:%s srcAS:%d dstAS:%d",
        record.ReceivedTime().Format(time.RFC3339),
			  record.RouterIP.String(),
			  record.DstIP.String(),
			  record.SrcIP.String(),
			  record.SrcPort,
			  record.DstPort,
			  record.SrcMask,
			  record.DstMask,
			  record.NextHopIP.String(),
			  record.SrcAS,
			  record.DstAS,
		)
    
    }
}

```

## StreamReader Example
Reads file one row at a time and returns records. This is generally faster and uses a lot less memory.

```go
package main

import (
	"bufio"
	"io"
	"log"
	"os"

	"github.com/chrispassas/nfdump"
)

func main() {

    var filePath = "testdata/nfcapd-large-lzo"
    var err error
    var nfs *nfdump.NFStream
    var f *os.File
    f, err = os.Open(filePath)
    if err != nil {
        log.Fatalf("[ERROR] os.Open error:%#+v", err)
    }
    defer f.Close()

    var reader = bufio.NewReader(f)
    nfs, err = nfdump.StreamReader(reader)
    if err != nil {
        log.Fatalf("[ERROR] nfdump.StreamReader error:%#+v", err)
    }
    
    var record *NFRecord
    for {
	if record, err = nfs.Row(); err == io.EOF {
	    goto Stop
	} else if err != nil {
	    log.Printf("[ERROR] nfs.Row() error:%v", err)
	    goto Stop
	}

	log.Printf("Received:%s routerIP:%s srcIP:%s dstIP:%s srcPort:%d dstPort:%d srcMask:%d dstMask:%d ipNextHop:%s srcAS:%d dstAS:%d",
        record.ReceivedTime().Format(time.RFC3339),
			  record.RouterIP.String(),
			  record.DstIP.String(),
			  record.SrcIP.String(),
			  record.SrcPort,
			  record.DstPort,
			  record.SrcMask,
			  record.DstMask,
			  record.NextHopIP.String(),
			  record.SrcAS,
			  record.DstAS,
		)

	}
Stop:

}

```
