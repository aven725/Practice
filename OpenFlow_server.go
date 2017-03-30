package main

import (
	"./OFprotocol"
	"encoding/hex"
	"fmt"
	"net"
	"os"
)

func main() {
	netListen, err := net.Listen("tcp", ":9988")
	CheckError(err)

	defer netListen.Close()

	Log("Waiting for clients")
	for {
		conn, err := netListen.Accept()
		if err != nil {
			continue
		}

		Log(conn.RemoteAddr().String(), " tcp connect success")
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	//声明一个临时缓冲区，用来存储被截断的数据
	tmpBuffer := make([]byte, 0)

	//声明一个管道用于接收解包的数据
	readerChannel := make(chan []byte, 16)
	go reader(readerChannel)

	buffer := make([]byte, 2048)
	for {
		n, err := conn.Read(buffer)
		// Log("N:", n, "B:", hex.EncodeToString(buffer[:n]))
		if err != nil {
			Log(conn.RemoteAddr().String(), " connection error: ", err)
			return
		}

		tmpBuffer = OFprotocol.Unpack(append(tmpBuffer, buffer[:n]...), readerChannel)
	}
}

func reader(readerChannel chan []byte) {
	for {
		select {
		case data := <-readerChannel:
			// Log("ANS:", hex.EncodeToString(data))
		}
	}
}

func Log(v ...interface{}) {
	fmt.Println(v...)
}

func CheckError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
