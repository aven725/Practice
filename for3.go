package main

import (
	//"bytes"
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

var (
	device       string = "brLAN"
	snapshot_len int32  = 2000
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = pcap.BlockForever
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

func main() {
	// Open Sdevice
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	fmt.Println("Only capturing TCP port 6653 packets.")

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Let's see if the packet is IP (even though the ether type told us)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			//fmt.Println("IPv4 layer detected.")
			ip, _ := ipLayer.(*layers.IPv4)

			SrcIP := net.ParseIP("192.168.10.11")
			DstIP := net.ParseIP("192.168.0.2")

			if SrcIP.Equal(ip.SrcIP) {
				if DstIP.Equal(ip.DstIP) {
					fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
					fmt.Println("Protocol: ", ip.Protocol)
					fmt.Println()
					// get packet byte and lenght
					packet_byte := packet.Data()
					packetOut := packet_byte
					packetOut[30] = 140 //
					packetOut[31] = 120
					packetOut[32] = 16
					packetOut[33] = 82
					fmt.Println("packet_byte:", hex.EncodeToString(packet_byte))
					fmt.Println("packet__Out:", hex.EncodeToString(packetOut))
					fmt.Println("ip__Payload:", hex.EncodeToString(ip.Payload))

					ipLayer2 := &layers.IPv4{
						SrcIP: net.IP{192, 168, 10, 11},
						DstIP: net.IP{140, 120, 16, 82},
					}

					ethernetLayer := &layers.Ethernet{
						DstMAC: net.HardwareAddr{0x7e, 0x6e, 0xf8, 0x44, 0x26, 0x4e}, //7e:6e:f8:44:26:4e
						SrcMAC: net.HardwareAddr{0x90, 0x2b, 0x34, 0x00, 0x01, 0x01}, //90:2b:34:00:01:01
					}

					// And create the packet with the layers
					buffer = gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buffer, options,
						ethernetLayer,
						ipLayer2,
						gopacket.Payload(ip.Payload),
					)
					outgoingPacket := buffer.Bytes()
					fmt.Println("outgoingPacket:", hex.EncodeToString(outgoingPacket))
					// Send our packet
					err = handle.WritePacketData(outgoingPacket)
					if err != nil {
						log.Fatal(err)
					}
				}
			}
		}

		// ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		// if ethernetLayer != nil {
		// 	fmt.Println("Ethernet layer detected.")
		// 	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		// 	SrcByte := []byte(ethernetPacket.SrcMAC)
		// 	// DstByte := []byte(ethernetPacket.DstMAC)

		// 	//if bytes.Equal(SrcByte, []byte{144, 43, 52, 0, 1, 1}) {
		// 	if !bytes.Equal(SrcByte, []byte{0xbe, 0xb4, 0xb2, 0x67, 0xdc, 0x44}) {
		// 		// fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		// 		// fmt.Println("Source MAC: ", []byte(ethernetPacket.SrcMAC))
		// 		// fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// 		// // Ethernet type is typically IPv4 but could be ARP or other
		// 		// fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		// 		// fmt.Println()

		// 		// get packet byte and lenght
		// 		packet_byte := packet.Data()
		// 		fmt.Println(hex.EncodeToString(packet_byte))
		// 		// Send our packet
		// 		err = handle.WritePacketData(packet_byte)
		// 		if err != nil {
		// 			log.Fatal(err)
		// 		}
		// 	}

		// }

	}

}
