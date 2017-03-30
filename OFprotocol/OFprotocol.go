//通讯协议处理，主要处理封包和解包的过程
package OFprotocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	// "fmt"
)

const (
	ConstHeader         = "04"
	ConstHeaderLength   = 2
	ConstSaveDataLength = 2
)

//封包
func Packet(message []byte) []byte {
	return append(append([]byte(ConstHeader), IntToBytes(len(message))...), message...)
}

//解包
func Unpack(buffer []byte, readerChannel chan []byte) []byte {
	// fmt.Println("In Unpack")
	length := len(buffer)

	var i int
	for i = 0; i < length; i = i + 1 {
		// fmt.Println("len:", length, "In Unpack i:", i)
		if length < i+ConstHeaderLength+ConstSaveDataLength {
			// fmt.Println("In Unpack length < i+ConstHeaderLength+ConstSaveDataLength")
			break
		}
		if hex.EncodeToString(buffer[i:i+ConstHeaderLength-1]) == ConstHeader {
			messageLength := BytesToInt(buffer[i+ConstHeaderLength : i+ConstHeaderLength+ConstSaveDataLength])
			// fmt.Println("messageLength:", messageLength)
			if length < i+messageLength {
				break
			}
			data := buffer[i : i+messageLength]
			readerChannel <- data

			i += messageLength - 1
		}
	}
	// fmt.Println("len:", length, "IF i:", i)
	if i == length {
		// fmt.Println("i=length")
		return make([]byte, 0)
	}
	// fmt.Println("return:", buffer[i:])
	return buffer[i:]
}

//整形转换成字节
func IntToBytes(n int) []byte {
	x := uint16(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

//字节转换成整形
func BytesToInt(b []byte) int {
	bytesBuffer := bytes.NewBuffer(b)

	var x uint16
	binary.Read(bytesBuffer, binary.BigEndian, &x)

	return int(x)
}
