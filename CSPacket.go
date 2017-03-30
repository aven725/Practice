package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

var (
	device       string = "eth1"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Send raw bytes over wire
	rawBytes := []byte{10, 20, 30}
	err = handle.WritePacketData(rawBytes)
	if err != nil {
		log.Fatal(err)
	}

	// Create a properly formed packet, just with
	// empty details. Should fill out MAC addresses,
	// IP addresses, etc.
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.TCP{},
		gopacket.Payload(rawBytes),
	)
	outgoingPacket := buffer.Bytes()
	// Send our packet
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}

	// This time lets fill out some information
	ipLayer := &layers.IPv4{
		SrcIP: net.IP{140, 120, 15, 182},
		DstIP: net.IP{140, 120, 15, 183},
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0x00, 0x1b, 0x21, 0xcf, 0x96, 0xe3},
		DstMAC: net.HardwareAddr{0x38, 0xD5, 0x47, 0x11, 0x31, 0x63},
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(22222),
		DstPort: layers.TCPPort(22222),
	}
	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	outgoingPacket = buffer.Bytes()

	fmt.Println(outgoingPacket)

}
