package extended_uuid

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"hash/crc32"
	"strings"
)


type ExUuid struct {
	Uuid *uuid.UUID
	additionalData []uint32
}

func Parse(exUuidText string, isLittleEndian bool) (*ExUuid, error) {
	var exUuid ExUuid
	uuidText := exUuidText[len(exUuidText) - 36:len(exUuidText)]
	uuid, err := uuid.Parse(uuidText)
	if err != nil {
		return &exUuid, errors.New("fail to parse uuid")
	}
	data := exUuidText[0: len(exUuidText) - 37]
	segments := strings.Split(data, "-")
	for i := 0; i < len(segments); i++ {
		segment := segments[i]
		if len(segment) != 8 {
			return &exUuid, errors.New("bad format for ExUuid")
		}
		bytes, err := hex.DecodeString(segment)
		if err != nil {
			return &exUuid, errors.New("bad format for ExUuid")
		}
		if isLittleEndian {
			exUuid.additionalData = append(exUuid.additionalData, binary.BigEndian.Uint32(bytes))
		} else {
			exUuid.additionalData = append(exUuid.additionalData, binary.LittleEndian.Uint32(bytes))
		}
	}
	exUuid.Uuid = &uuid

	return &exUuid, nil
}

type ExUuidReader struct {
	offset uint
	bytes []byte
}

func (r *ExUuidReader) ReadByte() byte {
	byte := r.bytes[r.offset]
	r.offset = r.offset + 1
	return byte
}

func NewExUuidReader(exUuid *ExUuid, isLittleEndian bool) *ExUuidReader {
	var reader ExUuidReader
	bytes, err := read(exUuid, isLittleEndian)
	if err == nil {
		reader.bytes = bytes
	}
	reader.offset = 0
	return &reader
}

func reverseArray(array []byte) []byte {
	var result []byte
	for i := len(array) - 1; i >= 0; i-- {
		result = append(result, array[i])
	}
	return result
}

func UuidToBytesArray(uuid *uuid.UUID) ([]byte, error) {
	var result []byte
	uuidBytes, err := uuid.MarshalBinary()
	if err != nil {
		return result, err
	}
	a := reverseArray(uuidBytes[0:4])
	b := reverseArray(uuidBytes[4:6])
	c := reverseArray(uuidBytes[6:8])
	result = append(result, a[:]...)
	result = append(result, b[:]...)
	result = append(result, c[:]...)
	result = append(result, uuidBytes[8:]...)
	return result, nil
}

func read(exUuid *ExUuid, isLittleEndian bool) ([]byte, error) {
	var bytes []byte

	for i := 0; i < len(exUuid.additionalData); i++ {
		cipher := exUuid.additionalData[i]

		var byteStream []byte
		for y := 0; y < i; y++ {
			if isLittleEndian {
				additionalDataBinary := make([]byte, 4)
				binary.LittleEndian.PutUint32(additionalDataBinary, exUuid.additionalData[y])
				byteStream = append(byteStream, additionalDataBinary[:]...)
			} else {
				additionalDataBinary := make([]byte, 4)
				binary.BigEndian.PutUint32(additionalDataBinary, exUuid.additionalData[y])
				byteStream = append(byteStream, additionalDataBinary[:]...)
			}
		}
		uuidBytes, err := UuidToBytesArray(exUuid.Uuid)
		if err != nil {
			return byteStream, err
		}
		byteStream = append(byteStream, uuidBytes[:]...)
		crc := crc32.NewIEEE()
		crc.Write(byteStream)
		key := crc.Sum32()
		values := cipher ^ key
		valueBytes := make([]byte, 4)
		if isLittleEndian {
			binary.LittleEndian.PutUint32(valueBytes, values)
		} else {
			binary.BigEndian.PutUint32(valueBytes, values)
		}
		bytes = append(bytes, valueBytes[:]...)
	}




	return bytes, nil
}
