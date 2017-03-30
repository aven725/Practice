package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

func sender(conn net.Conn) {
	for i := 0; i < 5; i++ {
		// str := "040a005c00000000ffffffff0032000000000000000000000001000c80000004000000030000000000002ebcef59329fba594094349c080045000024a2c64000401184000a0000020a000001aa3d138900102baf0000000000000256"
		// str := "040a007800000000ffffffff004e000000000000000000000001000c80000004000000010000000000003333ff00000100000000000186dd6000000000183aff00000000000000000000000000000000ff0200000000000000000001ff00000187007b2500000000fe80000000000000020000fffe000001"
		str := "0402000800000000"
		packetin, _ := hex.DecodeString(str)
		conn.Write([]byte(packetin))
		// str2 := "0402000800000000"
		// packetin2, _ := hex.DecodeString(str2)
		// conn.Write([]byte(packetin2))
	}
	fmt.Println("send over")
}

func main() {
	server := "127.0.0.1:9988"
	tcpAddr, err := net.ResolveTCPAddr("tcp4", server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}

	defer conn.Close()
	fmt.Println("connect success")
	go sender(conn)
	for {
		time.Sleep(1 * 1e9)
	}
}
