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
	Sdevice      string = "brLAN"
	Ddevice      string = "tapcloud01" //"tapOut"
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
	fmt.Println("brLAN to tapcloud01")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			fmt.Println("Ethernet layer detected.")
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

			SrcByte := []byte(ethernetPacket.SrcMAC)
			// DstByte := []byte(ethernetPacket.DstMAC)

			if bytes.Equal(SrcByte, []byte{0x7e, 0x6e, 0xf8, 0x44, 0x26, 0x4e}) {

				//if !bytes.Equal(SrcByte, []byte{0xbe, 0xb4, 0xb2, 0x67, 0xdc, 0x44}) {
				// fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
				// fmt.Println("Source MAC: ", []byte(ethernetPacket.SrcMAC))
				// fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
				// // Ethernet type is typically IPv4 but could be ARP or other
				// fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
				// fmt.Println()

				// get packet byte and lenght
				packet_byte := packet.Data()
				// if !bytes.Equal(DstByte, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) {
				// 	packet_byte[0] = 0x3a
				// 	packet_byte[1] = 0x37
				// 	packet_byte[2] = 0xdc
				// 	packet_byte[3] = 0x84
				// 	packet_byte[4] = 0x52
				// 	packet_byte[5] = 0x75
				// }
				fmt.Println(hex.EncodeToString(packet_byte))
				// Send our packet
				err = dhandle.WritePacketData(packet_byte)
				if err != nil {
					log.Fatal(err)
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
