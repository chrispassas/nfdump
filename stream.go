package nfdump

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/rasky/go-lzo"
)

// NFStream keeps track of non record fields while stream processing file
type NFStream struct {
	Header     NFHeader
	StatRecord NFStatRecord

	r                 io.Reader
	blockHeader       NFBlockHeader
	blockIndex        int
	blockRecordCount  int
	blockData         []byte
	decompressedBlock []byte
	readNewBlock      bool
	recordHeader      NFRecordHeader
	start             int
	extMap            map[uint16][]uint16
	Exporters         map[uint16]NFExporterInfoRecord
	ExporterStats     map[uint32]NFExporterStatRecord
	SamplerInfo       map[uint16]NFSamplerInfoRecord
}

// StreamReader read nfdump file record by record with minimal memory usage
func StreamReader(r io.Reader) (nfs *NFStream, err error) {

	nfs = &NFStream{
		r:             r,
		readNewBlock:  true,
		extMap:        make(map[uint16][]uint16),
		Exporters:     make(map[uint16]NFExporterInfoRecord),
		ExporterStats: make(map[uint32]NFExporterStatRecord),
		SamplerInfo:   make(map[uint16]NFSamplerInfoRecord),
	}

	if err = binary.Read(nfs.r, binary.LittleEndian, &nfs.Header); err != nil {
		err = ErrFailedReadFileHeader
		return nfs, err
	}

	if nfs.Header.Magic != magic {
		err = ErrBadMagic
		return nfs, err
	}

	if nfs.Header.Version != layoutVersion {
		err = ErrUnsupportedFileVersion
		return nfs, err
	}

	if err = binary.Read(nfs.r, binary.LittleEndian, &nfs.StatRecord); err != nil {
		err = ErrFailedReadStatRecord
		return nfs, err
	}

	return nfs, err
}

// Row each call will return an NFRecord struct or an error. io.EOF error means end of file.
func (nfs *NFStream) Row() (record NFRecord, err error) {

	var (
		ok              bool
		packetCountSize int
		ipSize          int
		recordExtID     uint16
		readOffset      int
		byteCountSize   int
		exts            []uint16
	)

NextBlock:
	if nfs.readNewBlock {
		nfs.readNewBlock = false
		if err = binary.Read(nfs.r, binary.LittleEndian, &nfs.blockHeader); err == io.EOF {
			return
		} else if err != nil {
			err = ErrFailedReadBlockHeader
			return record, err
		}

		nfs.blockIndex++

		if len(nfs.blockData) < int(nfs.blockHeader.Size) {
			nfs.blockData = make([]byte, nfs.blockHeader.Size)
		}

		if err = binary.Read(nfs.r, binary.LittleEndian, nfs.blockData[:nfs.blockHeader.Size]); err == io.EOF {
			return record, err
		} else if err != nil {
			err = fmt.Errorf("Read Block Failed blockIndex:%d error:%w", nfs.blockIndex, err)
			return record, err
		}

		// Only block type 2 is currently supported, any other types of data will be skipped
		if nfs.blockHeader.ID != 2 {
			nfs.readNewBlock = true
			goto NextBlock
		}

		if (nfs.Header.Flags & compressionMask) == 0 {
			nfs.decompressedBlock = nfs.blockData[:nfs.blockHeader.Size]
		} else if (nfs.Header.Flags & lzoCompressed) > 0 {
			if nfs.decompressedBlock, err = lzo.Decompress1X(bytes.NewReader(nfs.blockData[:nfs.blockHeader.Size]), 0, 0); err != nil {
				err = fmt.Errorf("lzo.Decompress1X() failed error:%w", err)
				return record, err
			}
		} else if (nfs.Header.Flags & lz4Compressed) > 0 {
			err = fmt.Errorf("LZ4 compression not supported")
			return record, err
			// if _, err = lz4.Decode(nfs.decompressedBlock, blockData); err != nil {
			// 	err = errors.Wrapf(err, "lz4.Decode() failed")
			// 	return record, err
			// }
		} else if (nfs.Header.Flags & bz2Compressed) > 0 {
			err = fmt.Errorf("BZ2 compression not supported")
			return record, err
		} else {
			err = fmt.Errorf("Unsupported File Flag Compression:%d", nfs.Header.Flags)
			return record, err
		}
		nfs.blockRecordCount = 0
		nfs.start = 0
	}

	// START Record
NextRecord:
	nfs.blockRecordCount++
	nfs.recordHeader.Type = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][0:2])
	nfs.recordHeader.Size = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][2:4])

	if nfs.recordHeader.Size == 0 {
		err = fmt.Errorf("Corrupt file, bad record size:%d", nfs.recordHeader.Size)
		return record, err
	}

	// Keep count of how many of each record type
	// nff.Meta.RecordIDCount[recordHeader.Type]++
	switch nfs.recordHeader.Type {
	case ExtensionMapRecordHeadType:
		var mapID = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][4:6])
		var extSize = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][6:8])

		// extSize == 0 extension map v2
		// extSize > 0 extension map v1
		if extSize == 0 {
			err = fmt.Errorf("Unsupported extension map v2 file")
			return record, err
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

		// If mapID already empty it before adding new extMapID's
		if _, ok = nfs.extMap[mapID]; ok {
			nfs.extMap[mapID] = nil
		}

		for x = 0; x < ((nfs.recordHeader.Size - 8) / 2); x++ {
			extStart += 2
			extEnd += 2
			newExtMapID = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][extStart:extEnd])
			if newExtMapID > 48 {
				err = fmt.Errorf("Corrupt file, bad extMapID:%d mapID:%d", newExtMapID, mapID)
				return record, err
			}
			/*
				v1 extension map aligns to 32bit so its possible there could be a 0 mapID at the end
				When mapID is 0 just ignore it
			*/
			if newExtMapID != 0 {
				nfs.extMap[mapID] = append(nfs.extMap[mapID], newExtMapID)
			}
		}

		nfs.start += int(nfs.recordHeader.Size)
		goto NextRecord
	case ExporterInfoRecordHeadType:
		// Store Exporter in map 'exporters'
		var exporter NFExporterInfoRecord
		exporter.Version = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][4:8])
		exporter.SAFamily = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][24:26])
		exporter.SysID = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][26:28])
		exporter.ID = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][28:32])

		/*
			NFDump stores the exporter IP as 2 uint64 integers. If the second uint64 [16:24]
			is == 0 we assume its an IPv4 address and only need to use the [12:16] slice
		*/
		var ipNumber2 = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][16:24])
		if ipNumber2 == 0 {
			// IPv4
			exporter.IPAddr = nfs.decompressedBlock[nfs.start:][12:16]
		} else {
			// IPv6
			var tmpIP []byte
			tmpIP = append(tmpIP, nfs.decompressedBlock[nfs.start:][16:24]...)
			tmpIP = append(tmpIP, nfs.decompressedBlock[nfs.start:][8:16]...)
			exporter.IPAddr = tmpIP
		}

		nfs.Exporters[exporter.SysID] = exporter

		nfs.start += int(nfs.recordHeader.Size)
		goto NextRecord
	case SamplerInfoRecordHeadType:
		// Store Samplers in map 'Samplers'

		var sampler NFSamplerInfoRecord
		sampler.ID = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][4:8])
		sampler.Interval = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][8:12])
		sampler.Mode = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][12:14])
		sampler.ExporterSysID = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][14:16])

		nfs.SamplerInfo[sampler.ExporterSysID] = sampler

		nfs.start += int(nfs.recordHeader.Size)
		goto NextRecord
	case EmptyRecordHeadType:
		nfs.readNewBlock = true
		goto NextBlock
	case ExporterStatRecordHeadType:
		// Exporter statistics records

		var statCount uint32
		var statPosition uint32
		var statRecord NFExporterStatRecord

		statCount = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][4:8])

		for statPosition = 0; statPosition < statCount; statPosition++ {
			j := (statPosition * 24) + 8 // each stat record is 24 bytes + 8 for header/stat count

			statRecord.SysID = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][j : j+4])
			statRecord.SequenceFailures = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][j+4 : j+8])
			statRecord.Packets = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][j+8 : j+16])
			statRecord.Flows = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][j+16 : j+24])

			nfs.ExporterStats[statRecord.SysID] = statRecord
		}

		nfs.readNewBlock = true
		goto NextBlock
	default:
		if nfs.recordHeader.Type != 10 {
			nfs.start += int(nfs.recordHeader.Size)
			goto NextRecord
		}
	}

	record.Flags = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][4:6])
	recordExtID = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][6:8])
	record.MsecFirst = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][8:10])
	record.MsecLast = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][10:12])
	record.First = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][12:16])
	record.Last = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][16:20])
	record.FwdStatus = uint8(nfs.decompressedBlock[nfs.start:][20])
	record.TCPFlags = uint8(nfs.decompressedBlock[nfs.start:][21])
	record.Proto = uint8(nfs.decompressedBlock[nfs.start:][22])
	record.Tos = uint8(nfs.decompressedBlock[nfs.start:][23])

	if record.Proto == 1 || record.Proto == 58 {
		record.ICMPType = nfs.decompressedBlock[nfs.start:][27]
		record.ICMPCode = nfs.decompressedBlock[nfs.start:][26]
		record.SrcPort = 0
		record.DstPort = (uint16(record.ICMPType) * 256) + uint16(record.ICMPCode)
	} else {
		record.SrcPort = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][24:26])
		record.DstPort = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][26:28])
		record.ICMPType = 0
		record.ICMPCode = 0
	}

	record.ExporterSysID = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][28:30])
	record.Reserved = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][30:32])

	if (record.Flags & v6And) != 0 {
		// nff.Meta.IPv6Count++
		record.SrcIP = append(record.SrcIP, reverseByteSlice(nfs.decompressedBlock[nfs.start:][32:40])...)
		record.SrcIP = append(record.SrcIP, reverseByteSlice(nfs.decompressedBlock[nfs.start:][40:48])...)

		record.DstIP = append(record.DstIP, reverseByteSlice(nfs.decompressedBlock[nfs.start:][48:56])...)
		record.DstIP = append(record.DstIP, reverseByteSlice(nfs.decompressedBlock[nfs.start:][56:64])...)
		ipSize = 32

	} else {
		// nff.Meta.IPv4Count++
		record.SrcIP = reverseByteSlice(nfs.decompressedBlock[nfs.start:][32:36])
		record.DstIP = reverseByteSlice(nfs.decompressedBlock[nfs.start:][36:40])
		ipSize = 8
	}

	if (record.Flags & packetCount8Byte) != 0 {
		record.PacketCount = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][(32 + ipSize):][0:8])
		packetCountSize = 8
	} else {
		record.PacketCount = uint64(binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][(32 + ipSize):][0:4]))
		packetCountSize = 4
	}

	if (record.Flags & bytesCount8Byte) != 0 {
		record.ByteCount = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][(32 + packetCountSize + ipSize):][0:8])
		byteCountSize = 8
	} else {
		record.ByteCount = uint64(binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][(32 + packetCountSize + ipSize):][0:4]))
		byteCountSize = 4
	}

	readOffset = 32 + packetCountSize + ipSize + byteCountSize

	if exts, ok = nfs.extMap[recordExtID]; !ok {
		err = fmt.Errorf("Extension not in map, ext:%d", recordExtID)
		return record, err
	}

	for _, extID := range exts {
		switch extID {
		case 4:
			record.Input = uint32(binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][readOffset:][0:2]))
			readOffset += 2
			record.Output = uint32(binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][readOffset:][0:2]))
			readOffset += 2
		case 5:
			record.Input = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][readOffset:][0:4])
			readOffset += 4
			record.Output = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][readOffset:][0:4])
			readOffset += 4
		case 6:
			record.SrcAS = uint32(binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][readOffset:][0:2]))
			readOffset += 2
			record.DstAS = uint32(binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][readOffset:][0:2]))
			readOffset += 2
		case 7:
			record.SrcAS = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][readOffset:][0:4])
			readOffset += 4
			record.DstAS = binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][readOffset:][0:4])
			readOffset += 4
		case 8:
			record.DstTos = nfs.decompressedBlock[nfs.start:][readOffset:][0]
			readOffset++
			record.Dir = nfs.decompressedBlock[nfs.start:][readOffset:][0]
			readOffset++
			record.SrcMask = nfs.decompressedBlock[nfs.start:][readOffset:][0]
			readOffset++
			record.DstMask = nfs.decompressedBlock[nfs.start:][readOffset:][0]
			readOffset++
		case 9:
			record.NextHopIP = reverseByteSlice(nfs.decompressedBlock[nfs.start:][readOffset:][0:4])
			readOffset += 4
		case 10:
			record.NextHopIP = reverseByteSlice(nfs.decompressedBlock[nfs.start:][readOffset:][0:16])
			readOffset += 16
		case 11:
			record.BGPNextIP = reverseByteSlice(nfs.decompressedBlock[nfs.start:][readOffset:][0:4])
			readOffset += 4
		case 12:
			record.BGPNextIP = reverseByteSlice(nfs.decompressedBlock[nfs.start:][readOffset:][0:16])
			readOffset += 16
		case 13:
			record.SrcVlan = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][readOffset:][0:2])
			readOffset += 2
			record.DstVLan = binary.LittleEndian.Uint16(nfs.decompressedBlock[nfs.start:][readOffset:][0:2])
			readOffset += 2
		case 14:
			record.OutPkts = uint64(binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][readOffset:][0:4]))
			readOffset += 4
		case 15:
			record.OutPkts = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][readOffset:][0:8])
			readOffset += 8
		case 16:
			record.OutBytes = uint64(binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][readOffset:][0:4]))
			readOffset += 4
		case 17:
			record.OutBytes = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][readOffset:][0:8])
			readOffset += 8
		case 18:
			record.AggeFlows = uint64(binary.LittleEndian.Uint32(nfs.decompressedBlock[nfs.start:][readOffset:][0:4]))
			readOffset += 4
		case 19:
			record.AggeFlows = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][readOffset:][0:8])
			readOffset += 8
		case 20:
			// To be added later or as needed
			readOffset += 16
		case 21:
			// To be added later or as needed
			readOffset += 16
		case 22:
			// To be added later or as needed
			readOffset += 40
		case 23:
			record.RouterIP = reverseByteSlice(nfs.decompressedBlock[nfs.start:][readOffset:][0:4])
			readOffset += 4
		case 24:
			record.RouterIP = append(record.RouterIP, reverseByteSlice(nfs.decompressedBlock[nfs.start:][readOffset:][0:8])...)
			record.RouterIP = append(record.RouterIP, reverseByteSlice(nfs.decompressedBlock[nfs.start:][readOffset:][8:16])...)
			readOffset += 16
		case 25:
			// To be added later or as needed
			readOffset += 4
		case 26:
			// To be added later or as needed
			readOffset += 8
		case 27:
			record.Received = binary.LittleEndian.Uint64(nfs.decompressedBlock[nfs.start:][readOffset:][0:8])
			readOffset += 8
		case 28:
			// reserved
		case 29:
			// reserved
		case 30:
			// reserved
		case 31:
			// reserved
		case 32:
			// reserved
		case 33:
			// reserved
		case 34:
			// reserved
		case 35:
			// reserved
		case 36:
			// reserved
		case 37:
			// To be added later or as needed
			readOffset += 20
		case 38:
			// To be added later or as needed
			readOffset += 4
		case 39:
			// To be added later or as needed
			readOffset += 8
		case 40:
			// To be added later or as needed
			readOffset += 32
		case 41:
			// To be added later or as needed
			readOffset += 24
		case 42:
			// To be added later or as needed
			readOffset += 24
		case 43:
			// To be added later or as needed
			readOffset += 72
		case 44:
			// reserved
		case 45:
			// To be added later or as needed
			readOffset += 24
		case 46:
			// To be added later or as needed
			readOffset += 12
		case 47:
			// To be added later or as needed
			readOffset += 8
		case 48:
			// To be added later or as needed
			readOffset += 8
		}
	}

	nfs.start += int(nfs.recordHeader.Size)

	if nfs.blockHeader.NumRecords == uint32(nfs.blockRecordCount) {
		nfs.readNewBlock = true
	}

	return record, err
}
