package main

import (
	"encoding/hex"
	"fmt"
	"net"
)

func main() {
	//Connect TCP
	conn, err := net.Dial("tcp", "140.120.15.183:6653")
	if err != nil {
		fmt.Println(err)
	}
	defer conn.Close()

	//simple Read
	buffer := make([]byte, 1024)
	conn.Read(buffer)

	//simple write
	conn.Write([]byte("Hello from client"))
	fmt.Println(hex.EncodeToString([]byte("Hello from client")))
}
