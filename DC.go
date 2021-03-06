package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/hkwi/gopenflow"
	"io"
	"log"
	"time"
)

var (
	device       string = "eth1"
	snapshot_len int32  = 65535
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = pcap.BlockForever // 30 * time.Second
	handle       *pcap.Handle
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "tcp and port 6653"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing TCP port 6653 packets.")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	//fmt.Println(packetSource.Packets())
	// for packet := range packetSource.Packets() {
	// 	// Process packet here
	// 	fmt.Println(packet)
	// }
	packetData, _, perr := handle.ReadPacketData()

	if perr == nil {
		fmt.Print("tttttt:")
		fmt.Println(gopenflow.ReadMessage(packetData))
	} else {
		log.Println("error:", perr)
	}

	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println("Error:", err)
			continue
		}
		fmt.Println(packet)

	}
}
