package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	//"net"
	"bytes"
	"encoding/hex"
	"fmt"
	"time"
)

var (
	Sdevice      string = "brWAN"
	Ddevice      string = "tapcloud01"
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
	fmt.Println("brWAN to tapcloud01")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			fmt.Println("Ethernet layer detected.")
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

			SrcByte := []byte(ethernetPacket.SrcMAC)
			DstByte := []byte(ethernetPacket.DstMAC)

			//if bytes.Equal(SrcByte, []byte{0x90, 0x2b, 0x34, 0x00, 0x01, 0x01}) {
			if bytes.Equal(SrcByte, []byte{0x00, 0x1b, 0x21, 0xcf, 0x96, 0xe3}) {
				//if !bytes.Equal(SrcByte, []byte{0xbe, 0xb4, 0xb2, 0x67, 0xdc, 0x44}) {
				// fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
				// fmt.Println("Source MAC: ", []byte(ethernetPacket.SrcMAC))
				// fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
				// // Ethernet type is typically IPv4 but could be ARP or other
				// fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
				// fmt.Println()

				// get packet byte and lenght
				packet_byte := packet.Data()
				if bytes.Equal(DstByte, []byte{0x88, 0x5a, 0x92, 0x9a, 0x6c, 0x50}) {

					packet_byte[6] = 0x88
					packet_byte[7] = 0x5a
					packet_byte[8] = 0x5a
					packet_byte[9] = 0x9a
					packet_byte[10] = 0x6c
					packet_byte[11] = 0x50

					//3a:37:dc:84:52:75
					packet_byte[0] = 0x3a
					packet_byte[1] = 0x37
					packet_byte[2] = 0xdc
					packet_byte[3] = 0x84
					packet_byte[4] = 0x52
					packet_byte[5] = 0x75
					fmt.Println(hex.EncodeToString(packet_byte))
					// Send our packet
					err = dhandle.WritePacketData(packet_byte)
					if err != nil {
						log.Fatal(err)
					}
				}

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
