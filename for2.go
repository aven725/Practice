package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	//"bytes"
	"encoding/hex"
	"fmt"
	"time"
)

var (
	Sdevice      string = "brWAN"
	Ddevice      string = "brLAN" //"tapOut"
	snapshot_len int32  = 2000
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = pcap.BlockForever
	handle       *pcap.Handle
	dhandle      *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func main() {
	// Open Sdevice
	handle, err = pcap.OpenLive(Sdevice, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	dhandle, err = pcap.OpenLive(Ddevice, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer dhandle.Close()

	// // Set filter
	// var filter string = "tcp and port 6653"
	// err = handle.SetBPFFilter(filter)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	fmt.Println("Only capturing TCP port 6653 packets.")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		// Let's see if the packet is IP (even though the ether type told us)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			//fmt.Println("IPv4 layer detected.")
			ip, _ := ipLayer.(*layers.IPv4)

			SrcIP := net.ParseIP("140.120.16.82")
			//DstIP := net.ParseIP("192.168.0.2")

			if SrcIP.Equal(ip.SrcIP) {
				//if DstIP.Equal(ip.DstIP) {
				fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
				fmt.Println("Protocol: ", ip.Protocol)
				fmt.Println()
				packet_byte := packet.Data()
				fmt.Println(hex.EncodeToString(packet_byte))
				// Send our packet
				err = dhandle.WritePacketData(packet_byte)
				if err != nil {
					log.Fatal(err)
				}
				//}
			}

		}

	}

	// // Send raw bytes over wire
	// rawBytes := []byte{10, 20, 30}
	// err = handle.WritePacketData(rawBytes)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// // Create a properly formed packet, just with
	// // empty details. Should fill out MAC addresses,
	// // IP addresses, etc.
	// buffer = gopacket.NewSerializeBuffer()
	// gopacket.SerializeLayers(buffer, options,
	// 	&layers.Ethernet{},
	// 	&layers.IPv4{},
	// 	&layers.TCP{},
	// 	gopacket.Payload(rawBytes),
	// )
	// outgoingPacket := buffer.Bytes()

}
