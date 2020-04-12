# nfdump
NFDump File Reader


## ParseReader Example
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
