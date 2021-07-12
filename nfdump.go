/*
Package nfdump this libraries purpose is to allow a Go program to natively proess NFDump files without the need for CLI tools.
*/
package nfdump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/rasky/go-lzo"
)

const (
	//magic expected file magic value
	magic = 0xA50C

	//Compression types, currently only LZO is supported in this library
	// notCompressed   = 0x0
	lzoCompressed   = 0x1
	bz2Compressed   = 0x8
	lz4Compressed   = 0x10
	compressionMask = 0x19

	//Only 1 layout version is known/supported
	layoutVersion = 1
)

var (
	//ErrBadMagic file magic does not match expected value
	ErrBadMagic = fmt.Errorf("bad file magic")
)

//NFFile NFDump Go structure representation
type NFFile struct {
	Header        NFHeader
	StatRecord    NFStatRecord
	Records       []NFRecord
	Meta          NFMeta
	Exporters     map[uint16]NFExporterInfoRecord
	ExporterStats map[uint32]NFExporterStatRecord
	SamplerInfo   map[uint16]NFSamplerInfoRecord
}

//NFSamplerInfoRecord store router sampling information
type NFSamplerInfoRecord struct {
	// sampler data
	// id assigned by the exporting device
	ID uint32
	// sampling interval
	Interval uint32
	// sampling mode
	Mode uint16
	// internal reference to exporter
	ExporterSysID uint16
}

//NFExporterInfoRecord exporter info record
type NFExporterInfoRecord struct {
	// exporter version
	Version uint32
	// IP address
	IPAddr   net.IP
	SAFamily uint16
	// internal assigned ID
	SysID uint16
	// exporter ID/Domain ID/Observation Domain ID assigned by the device
	ID uint32
}

//NFExporterStatRecord exporter stats record
type NFExporterStatRecord struct {
	// internal assigned ID
	SysID uint32
	// total sequence failures/drops
	SequenceFailures uint32
	// packets per exporter
	Packets uint64
	// flows per exporter
	Flows uint64
}

//NFRecordHeader NFDump record header
//Size 4 bytes
type NFRecordHeader struct {
	Type uint16
	Size uint16
}

//NFRecord Size 32 bytes
//Most appear to be size 96 bytes (remainder 64)
type NFRecord struct {

	//Common Record Type
	Flags uint16

	// ExtMap        uint16

	//MsecFirst Flow Start Time Milliseconds
	MsecFirst uint16

	//MsecLast Flow End Time Milliseconds
	MsecLast uint16

	//First Flow Start Time Seconds since epoch
	First uint32

	//Last Flow End Time Seconds since epoch
	Last uint32

	FwdStatus     uint8
	TCPFlags      uint8
	Proto         uint8
	Tos           uint8
	SrcPort       uint16
	DstPort       uint16
	ExporterSysID uint16
	Reserved      uint16
	ICMPType      uint8
	ICMPCode      uint8

	//Required Extension 1
	SrcIP net.IP
	DstIP net.IP

	//Required Extension 2
	PacketCount uint64

	//Required Extension 3
	ByteCount uint64

	//Extension 4 & 5
	Input  uint32
	Output uint32

	//Extension 6 & 7
	SrcAS uint32
	DstAS uint32

	//Extension 8
	DstTos  uint8
	Dir     uint8
	SrcMask uint8
	DstMask uint8

	//Extension 9 & 10
	NextHopIP net.IP

	//Extension 11 & 12
	BGPNextIP net.IP

	//Extension 13
	SrcVlan uint16
	DstVLan uint16

	//Extension 14 & 15
	OutPkts uint64

	//Extension 16 & 17
	OutBytes uint64

	//Extension 18 & 19
	AggeFlows uint64

	//Extension 22

	//Extension 23
	RouterIP net.IP //Sending router IP

	// Extension 27
	//Received Received Time Milliseconds
	Received uint64

	//Extensions 20-44 to be implemented later/as needed
}

//ReceivedTime return Go time.Time representation of flow Received Time
func (r NFRecord) ReceivedTime() time.Time {
	if r.Received == 0 {
		return time.Unix(0, 0)
	}
	var seconds = int64(r.Received / 1000)
	return time.Unix(seconds, int64(r.Received)-(seconds*1000))
}

//StartTime return Go time.Time representation of flow Start Time
func (r NFRecord) StartTime() time.Time {
	if r.First == 0 && r.MsecFirst == 0 {
		return time.Unix(0, 0)
	}
	return time.Unix(int64(r.First), int64(r.MsecFirst)*1000000)
}

//StartTimeMS return end time in milliseconds (better for high performance)
func (r NFRecord) StartTimeMS() int64 {
	return ((int64(r.First) * 1000) + int64(r.MsecFirst))
}

//EndTime return Go time.Time representation of flow End Time
func (r NFRecord) EndTime() time.Time {
	if r.Last == 0 && r.MsecLast == 0 {
		return time.Unix(0, 0)
	}
	return time.Unix(int64(r.Last), int64(r.MsecLast)*1000000)
}

//EndTimeMS return end time in milliseconds (better for high performance)
func (r NFRecord) EndTimeMS() int64 {
	return ((int64(r.Last) * 1000) + int64(r.MsecLast))
}

//Duration return Go time.Duration of flow
func (r NFRecord) Duration() time.Duration {
	return r.EndTime().Sub(r.StartTime())
}

//DurationMilliseconds returns duration in milliseconds (better for high performance)
func (r NFRecord) DurationMilliseconds() int64 {
	return ((int64(r.Last) * 1000) + int64(r.MsecLast)) - ((int64(r.First) * 1000) + int64(r.MsecFirst))
}

//NFMeta store extra meta data/stats about NFDump file contents
type NFMeta struct {
	RecordIDCount map[uint16]int
	BlockIDCount  map[uint16]int
	IPv6Count     int
	IPv4Count     int
	ExtUsage      map[uint16]int
}

//NFStatRecord NFDump file aggregate stats
type NFStatRecord struct {
	NumFlows        uint64
	NumBytes        uint64
	NumPackets      uint64
	NumFlowsTCP     uint64
	NumFlowsUDP     uint64
	NumFlowsICMP    uint64
	NumFlowsOther   uint64
	NumBytesTCP     uint64
	NumBytesUDP     uint64
	NumBytesICMP    uint64
	NumBytesOther   uint64
	NumPacketsTCP   uint64
	NumPacketsUDP   uint64
	NumPacketsICMP  uint64
	NumPacketsOther uint64
	FirstSeen       uint32
	LastSeen        uint32
	MSecFirst       uint16
	MSecLast        uint16
	SequenceFailure uint32
}

//NFHeader NFDump file header
type NFHeader struct {
	Magic     uint16
	Version   uint16
	Flags     uint32
	NumBlocks uint32
	Ident     [128]byte
}

//NFBlockHeader NFDump Block Header
type NFBlockHeader struct {
	NumRecords uint32
	Size       uint32
	ID         uint16
	Flags      uint16
}

var (
	//v6And used to test for IPv6 or IPv4, this determines if we read 4 or 16 bytes per-IP field
	v6And = uint16(1)
	//packetCount8Byte used to determine if packet count is stored as 4 or 8 byte value
	packetCount8Byte = uint16(math.Pow(2, 1))
	//bytesCount8Byte used to determine if byte count is stored as 4 or 8 byte value
	bytesCount8Byte = uint16(math.Pow(2, 2))
)

//reverseByteSlice reverse a slice of bytes, currently used for IP fields
func reverseByteSlice(a []byte) []byte {

	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]
	}

	return a
}

//ParseReader parse NFDump file content in io.Reader and return netflow records and stats
func ParseReader(r io.Reader) (nff *NFFile, err error) {

	var (
		blockData         []byte
		decompressedBlock []byte
		blockIndex        uint32
		blockHeader       NFBlockHeader
		blockRecordCount  int
		ipSize            int
		packetCountSize   int
		byteCountSize     int
		readOffset        int
		start             int
		extMap            = make(map[uint16][]uint16)
		exts              []uint16
		recordExtID       uint16
		ok                bool
		recordHeader      NFRecordHeader
	)

	nff = &NFFile{
		Exporters:     make(map[uint16]NFExporterInfoRecord),
		ExporterStats: make(map[uint32]NFExporterStatRecord),
		SamplerInfo:   make(map[uint16]NFSamplerInfoRecord),
		Meta: NFMeta{
			RecordIDCount: make(map[uint16]int),
			BlockIDCount:  make(map[uint16]int),
			ExtUsage:      make(map[uint16]int),
		},
	}

	if err = binary.Read(r, binary.LittleEndian, &nff.Header); err != nil {
		err = errors.Wrapf(err, "Failed read NFFile Header")
		return
	}

	if nff.Header.Magic != magic {
		err = ErrBadMagic
		return
	}

	if nff.Header.Version != layoutVersion {
		err = errors.Wrap(err, "Unsupported File Version")
		return
	}

	if err = binary.Read(r, binary.LittleEndian, &nff.StatRecord); err != nil {
		err = errors.Wrapf(err, "Failed read StatRecord")
		return
	}

	//This allows avoiding a bunch of slice grow events
	nff.Records = make([]NFRecord, 0, nff.StatRecord.NumFlows)
NextBlock:
	for blockIndex = 1; blockIndex <= nff.Header.NumBlocks; blockIndex++ {
		if err = binary.Read(r, binary.LittleEndian, &blockHeader); err != nil {
			err = errors.Wrapf(err, "Failed read BlockHeader")
			return
		}

		nff.Meta.BlockIDCount[blockHeader.ID]++
		blockData = make([]byte, blockHeader.Size)

		if err = binary.Read(r, binary.LittleEndian, &blockData); err != nil {
			err = errors.Wrapf(err, "Read Block Failed blockIndex:%d", blockIndex)
			return
		}

		//Only block type 2 is currently supported, any other types of data will be skipped
		if blockHeader.ID != 2 {
			goto NextBlock
		}

		if (nff.Header.Flags & compressionMask) == 0 {
			decompressedBlock = blockData
		} else if (nff.Header.Flags & lzoCompressed) > 0 {
			if decompressedBlock, err = lzo.Decompress1X(bytes.NewReader(blockData), 0, 0); err != nil {
				err = errors.Wrapf(err, "lzo.Decompress1X() failed")
				return
			}
		} else if (nff.Header.Flags & lz4Compressed) > 0 {
			err = fmt.Errorf("LZ4 compression not supported")
			return
			// if _, err = lz4.Decode(decompressedBlock, blockData); err != nil {
			// 	err = errors.Wrapf(err, "lz4.Decode() failed")
			// 	return
			// }
		} else if (nff.Header.Flags & bz2Compressed) > 0 {
			err = fmt.Errorf("BZ2 compression not supported")
			return
		} else {
			err = fmt.Errorf("Unsupported File Flag Compression:%d", nff.Header.Flags)
			return
		}

		blockRecordCount = 0
		start = 0
	NextRecord:
		for {

			//Keep count on records in block
			blockRecordCount++
			recordHeader.Type = binary.LittleEndian.Uint16(decompressedBlock[start:][0:2])
			recordHeader.Size = binary.LittleEndian.Uint16(decompressedBlock[start:][2:4])

			//Keep count of how many of each record type
			nff.Meta.RecordIDCount[recordHeader.Type]++
			if recordHeader.Type == 2 {
				var mapID = binary.LittleEndian.Uint16(decompressedBlock[start:][4:6])
				var extSize = binary.LittleEndian.Uint16(decompressedBlock[start:][6:8])

				//extSize == 0 extension map v2
				//extSize > 0 extension map v1
				if extSize == 0 {
					err = fmt.Errorf("Unsupported extension map v2 file")
					return
				}
				var x uint16
				var extStart uint16 = 6
				var extEnd uint16 = 8
				var newExtMapID uint16
				/*
					Subtract 8 for the size of the record header, mapID and extSize.
					Type (2 byte) + Size (2 byte) + mapID (2 byte) + extSize (2 byte) = 8 bytes

					Divide by 2 to get the total number of uint16 (2 byte) extension ID's

					This is how to determine the total extensions in the record to read out and put in ext map.
				*/

				//If mapID already empty it before adding new extMapID's
				if _, ok = extMap[mapID]; ok {
					extMap[mapID] = nil
				}

				for x = 0; x < ((recordHeader.Size - 8) / 2); x++ {
					extStart += 2
					extEnd += 2
					newExtMapID = binary.LittleEndian.Uint16(decompressedBlock[start:][extStart:extEnd])
					if newExtMapID > 48 {
						err = fmt.Errorf("Corrupt file, bad extMapID:%d mapID:%d", newExtMapID, mapID)
						return
					}
					/*
						v1 extension map aligns to 32bit so its possible there could be a 0 mapID at the end
						When mapID is 0 just ignore it
					*/
					if newExtMapID != 0 {
						nff.Meta.ExtUsage[newExtMapID]++
						extMap[mapID] = append(extMap[mapID], newExtMapID)
					}
				}

				start += int(recordHeader.Size)

				continue NextRecord
			} else if recordHeader.Type == 7 {
				//Store Exporter in map 'exporters'
				var exporter NFExporterInfoRecord
				exporter.Version = binary.LittleEndian.Uint32(decompressedBlock[start:][4:8])
				exporter.SAFamily = binary.LittleEndian.Uint16(decompressedBlock[start:][24:26])
				exporter.SysID = binary.LittleEndian.Uint16(decompressedBlock[start:][26:28])
				exporter.ID = binary.LittleEndian.Uint32(decompressedBlock[start:][28:32])

				/*
					NFDump stores the exporter IP as 2 uint64 integers. If the second uint64 [16:24]
					is == 0 we assume its an IPv4 address and only need to use the [12:16] slice
				*/
				var ipNumber2 = binary.LittleEndian.Uint64(decompressedBlock[start:][16:24])
				if ipNumber2 == 0 {
					//IPv4
					exporter.IPAddr = decompressedBlock[start:][12:16]
				} else {
					//IPv6
					var tmpIP []byte
					tmpIP = append(tmpIP, decompressedBlock[start:][16:24]...)
					tmpIP = append(tmpIP, decompressedBlock[start:][8:16]...)
					exporter.IPAddr = tmpIP
				}

				nff.Exporters[exporter.SysID] = exporter

				start += int(recordHeader.Size)
				continue NextRecord
			} else if recordHeader.Type == 9 {
				//Store Samplers in map 'Samplers'

				var sampler NFSamplerInfoRecord
				sampler.ID = binary.LittleEndian.Uint32(decompressedBlock[start:][4:8])
				sampler.Interval = binary.LittleEndian.Uint32(decompressedBlock[start:][8:12])
				sampler.Mode = binary.LittleEndian.Uint16(decompressedBlock[start:][12:14])
				sampler.ExporterSysID = binary.LittleEndian.Uint16(decompressedBlock[start:][14:16])

				nff.SamplerInfo[sampler.ExporterSysID] = sampler

				start += int(recordHeader.Size)
				continue NextRecord
			} else if recordHeader.Type == 0 {
				continue NextBlock
			} else if recordHeader.Type == 8 {
				// Exporter statistics records

				var statCount uint32
				var statPosition uint32
				var statRecord NFExporterStatRecord

				statCount = binary.LittleEndian.Uint32(decompressedBlock[start:][4:8])

				for statPosition = 0; statPosition < statCount; statPosition++ {
					j := (statPosition * 24) + 8 // each stat record is 24 bytes + 8 for header/stat count

					statRecord.SysID = binary.LittleEndian.Uint32(decompressedBlock[start:][j : j+4])
					statRecord.SequenceFailures = binary.LittleEndian.Uint32(decompressedBlock[start:][j+4 : j+8])
					statRecord.Packets = binary.LittleEndian.Uint64(decompressedBlock[start:][j+8 : j+16])
					statRecord.Flows = binary.LittleEndian.Uint64(decompressedBlock[start:][j+16 : j+24])

					nff.ExporterStats[statRecord.SysID] = statRecord
				}

				continue NextBlock
			} else if recordHeader.Type != 10 {
				start += int(recordHeader.Size)
				continue NextRecord
			}

			var record NFRecord
			record.Flags = binary.LittleEndian.Uint16(decompressedBlock[start:][4:6])
			recordExtID = binary.LittleEndian.Uint16(decompressedBlock[start:][6:8])
			record.MsecFirst = binary.LittleEndian.Uint16(decompressedBlock[start:][8:10])
			record.MsecLast = binary.LittleEndian.Uint16(decompressedBlock[start:][10:12])
			record.First = binary.LittleEndian.Uint32(decompressedBlock[start:][12:16])
			record.Last = binary.LittleEndian.Uint32(decompressedBlock[start:][16:20])
			record.FwdStatus = uint8(decompressedBlock[start:][20])
			record.TCPFlags = uint8(decompressedBlock[start:][21])
			record.Proto = uint8(decompressedBlock[start:][22])
			record.Tos = uint8(decompressedBlock[start:][23])

			if record.Proto == 1 {
				record.ICMPType = uint8(decompressedBlock[start:][27])
				record.ICMPCode = uint8(decompressedBlock[start:][26])
				record.SrcPort = 0
				record.DstPort = (uint16(record.ICMPType) * 256) + uint16(record.ICMPCode)
			} else {
				record.SrcPort = binary.LittleEndian.Uint16(decompressedBlock[start:][24:26])
				record.DstPort = binary.LittleEndian.Uint16(decompressedBlock[start:][26:28])
				record.ICMPType = 0
				record.ICMPCode = 0
			}

			record.ExporterSysID = binary.LittleEndian.Uint16(decompressedBlock[start:][28:30])
			record.Reserved = binary.LittleEndian.Uint16(decompressedBlock[start:][30:32])

			if (record.Flags & v6And) != 0 {
				nff.Meta.IPv6Count++
				record.SrcIP = reverseByteSlice(decompressedBlock[start:][32:48])
				record.DstIP = reverseByteSlice(decompressedBlock[start:][48:64])
				ipSize = 32

			} else {
				nff.Meta.IPv4Count++
				record.SrcIP = reverseByteSlice(decompressedBlock[start:][32:36])
				record.DstIP = reverseByteSlice(decompressedBlock[start:][36:40])
				ipSize = 8
			}

			if (record.Flags & packetCount8Byte) != 0 {
				record.PacketCount = binary.LittleEndian.Uint64(decompressedBlock[start:][(32 + ipSize):][0:8])
				packetCountSize = 8
			} else {
				record.PacketCount = uint64(binary.LittleEndian.Uint32(decompressedBlock[start:][(32 + ipSize):][0:4]))
				packetCountSize = 4
			}

			if (record.Flags & bytesCount8Byte) != 0 {
				record.ByteCount = binary.LittleEndian.Uint64(decompressedBlock[start:][(32 + packetCountSize + ipSize):][0:8])
				byteCountSize = 8
			} else {
				record.ByteCount = uint64(binary.LittleEndian.Uint32(decompressedBlock[start:][(32 + packetCountSize + ipSize):][0:4]))
				byteCountSize = 4
			}

			readOffset = 32 + packetCountSize + ipSize + byteCountSize

			if exts, ok = extMap[recordExtID]; !ok {
				err = fmt.Errorf("Extension not in map, ext:%d", recordExtID)
				return
			}

			for _, extID := range exts {
				switch extID {
				case 4:
					record.Input = uint32(binary.LittleEndian.Uint16(decompressedBlock[start:][readOffset:][0:2]))
					readOffset += 2
					record.Output = uint32(binary.LittleEndian.Uint16(decompressedBlock[start:][readOffset:][0:2]))
					readOffset += 2
				case 5:
					record.Input = binary.LittleEndian.Uint32(decompressedBlock[start:][readOffset:][0:4])
					readOffset += 4
					record.Output = binary.LittleEndian.Uint32(decompressedBlock[start:][readOffset:][0:4])
					readOffset += 4
				case 6:
					record.SrcAS = uint32(binary.LittleEndian.Uint16(decompressedBlock[start:][readOffset:][0:2]))
					readOffset += 2
					record.DstAS = uint32(binary.LittleEndian.Uint16(decompressedBlock[start:][readOffset:][0:2]))
					readOffset += 2
				case 7:
					record.SrcAS = binary.LittleEndian.Uint32(decompressedBlock[start:][readOffset:][0:4])
					readOffset += 4
					record.DstAS = binary.LittleEndian.Uint32(decompressedBlock[start:][readOffset:][0:4])
					readOffset += 4
				case 8:
					record.DstTos = decompressedBlock[start:][readOffset:][0]
					readOffset += 1
					record.Dir = decompressedBlock[start:][readOffset:][0]
					readOffset += 1
					record.SrcMask = decompressedBlock[start:][readOffset:][0]
					readOffset += 1
					record.DstMask = decompressedBlock[start:][readOffset:][0]
					readOffset += 1
				case 9:
					record.NextHopIP = reverseByteSlice(decompressedBlock[start:][readOffset:][0:4])
					readOffset += 4
				case 10:
					record.NextHopIP = reverseByteSlice(decompressedBlock[start:][readOffset:][0:16])
					readOffset += 16
				case 11:
					record.BGPNextIP = reverseByteSlice(decompressedBlock[start:][readOffset:][0:4])
					readOffset += 4
				case 12:
					record.BGPNextIP = reverseByteSlice(decompressedBlock[start:][readOffset:][0:16])
					readOffset += 16
				case 13:
					record.SrcVlan = binary.LittleEndian.Uint16(decompressedBlock[start:][readOffset:][0:2])
					readOffset += 2
					record.DstVLan = binary.LittleEndian.Uint16(decompressedBlock[start:][readOffset:][0:2])
					readOffset += 2
				case 14:
					record.OutPkts = uint64(binary.LittleEndian.Uint32(decompressedBlock[start:][readOffset:][0:4]))
					readOffset += 4
				case 15:
					record.OutPkts = binary.LittleEndian.Uint64(decompressedBlock[start:][readOffset:][0:8])
					readOffset += 8
				case 16:
					record.OutBytes = uint64(binary.LittleEndian.Uint32(decompressedBlock[start:][readOffset:][0:4]))
					readOffset += 4
				case 17:
					record.OutBytes = binary.LittleEndian.Uint64(decompressedBlock[start:][readOffset:][0:8])
					readOffset += 8
				case 18:
					record.AggeFlows = uint64(binary.LittleEndian.Uint32(decompressedBlock[start:][readOffset:][0:4]))
					readOffset += 4
				case 19:
					record.AggeFlows = binary.LittleEndian.Uint64(decompressedBlock[start:][readOffset:][0:8])
					readOffset += 8
				case 20:
					//To be added later or as needed
					readOffset += 16
				case 21:
					//To be added later or as needed
					readOffset += 16
				case 22:
					//To be added later or as needed
					readOffset += 40
				case 23:
					record.RouterIP = reverseByteSlice(decompressedBlock[start:][readOffset:][0:4])
					readOffset += 4
				case 24:
					/*
						Need an IPv6 example to ensure we are parsing the IP correctly.
					*/
					// var tmpIP []byte
					// tmpIP = append(tmpIP, decompressedBlock[start:][8:16]...)
					// tmpIP = append(tmpIP, decompressedBlock[start:][0:8]...)
					// record.RouterIP = tmpIP
					readOffset += 16
				case 25:
					//To be added later or as needed
					readOffset += 4
				case 26:
					//To be added later or as needed
					readOffset += 8
				case 27:
					record.Received = binary.LittleEndian.Uint64(decompressedBlock[start:][readOffset:][0:8])
					readOffset += 8
				case 28:
					//reserved
				case 29:
					//reserved
				case 30:
					//reserved
				case 31:
					//reserved
				case 32:
					//reserved
				case 33:
					//reserved
				case 34:
					//reserved
				case 35:
					//reserved
				case 36:
					//reserved
				case 37:
					//To be added later or as needed
					readOffset += 20
				case 38:
					//To be added later or as needed
					readOffset += 4
				case 39:
					//To be added later or as needed
					readOffset += 8
				case 40:
					//To be added later or as needed
					readOffset += 32
				case 41:
					//To be added later or as needed
					readOffset += 24
				case 42:
					//To be added later or as needed
					readOffset += 24
				case 43:
					//To be added later or as needed
					readOffset += 72
				case 44:
					//reserved
				case 45:
					//To be added later or as needed
					readOffset += 24
				case 46:
					//To be added later or as needed
					readOffset += 12
				case 47:
					//To be added later or as needed
					readOffset += 8
				case 48:
					//To be added later or as needed
					readOffset += 8
				}
			}

			start += int(recordHeader.Size)
			nff.Records = append(nff.Records, record)

			if blockHeader.NumRecords == uint32(blockRecordCount) {
				continue NextBlock
			}

		}
	}

	return
}
