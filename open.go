package main

import (
	"encoding/hex"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
	//"net"
	"syscall"
)

const (
	OFP_OPENFLOW_13 int = 4
	OFP_PACKET_IN   int = 10
	OFP_PACKET_OUT  int = 13
)

var (
	device       string = "vtapcloud01"
	snapshot_len int32  = 65535
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = pcap.BlockForever // 30 * time.Second
	handle       *pcap.Handle

	ethernet_len   int = 14
	ethernet_type1 int = 12 // byte[12] 08
	ethernet_type2 int = 13 // byte[13] 00 -> ip 06 ->arp

	ipv4_len  int = -1 // byte[14] % 16 *4 = header lenght
	ipv4_type int = 23 // byte[23] 06 ->tcp ipv4_len+9

	tcp_len int = -1 // byte[ipv4_len+14+12] /16 *4 = tcp header lenght

	openflow_version int = -1 // byte[sumlen+1] 04->openflow1.3

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
	for packet := range packetSource.Packets() {

		// get packet byte and lenght
		packet_byte := packet.Data()
		packet_size := int(len(packet_byte))
		//fmt.Println("packet_size:", packet_size)
		if packet_size >= 0 {
			// Process packet here
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {

				ipv4_len = int(packet_byte[14] % 16 * 4)

				// fmt.Println("ipv4_len: ", ipv4_len)

				tcp_len = int(packet_byte[ethernet_len+ipv4_len+12] / 16 * 4)

				// fmt.Println("tcp_len: ", tcp_len)

				total_tcp_len := int(ethernet_len + ipv4_len + tcp_len)

				// check openflow packet
				if packet_size > total_tcp_len {

					openflow_version := int(packet_byte[total_tcp_len])
					//fmt.Println("openflow_version: ", openflow_version)

					// OpenFlow 1.3
					if openflow_version == OFP_OPENFLOW_13 {

						openflow_type := int(packet_byte[total_tcp_len+1])
						//fmt.Println("openflow_type: ", openflow_type, total_tcp_len+1)

						// Packet-In -> 10 Packet-Out-> 13
						if openflow_type == OFP_PACKET_IN { //|| (openflow_type == OFP_PACKET_OUT) {

							//bufferID := []byte

							OpenFlowData := []byte(packet_byte[total_tcp_len+42:])

							udp_ipv4_len := int(OpenFlowData[14] % 16 * 4)
							fmt.Println("udp_ipv4_len:", int(udp_ipv4_len))

							// save len
							save_len := int(total_tcp_len + 42 + 14 + udp_ipv4_len + 8)

							// packet_byte[save_len:] -> padload
							fmt.Println("packet_byte", hex.EncodeToString(packet_byte[:save_len]))

							// // create udp
							// packetUDP := gopacket.NewPacket(OpenFlowData, layers.LayerTypeEthernet, gopacket.Default)

							// udpLayer := packetUDP.Layer(layers.LayerTypeUDP)
							// if udpLayer != nil {
							// 	fmt.Println("UDP layer detected.")
							// 	udp, _ := udpLayer.(*layers.UDP)

							// 	fmt.Printf("UDP_Payload lenght:", len(udp.Payload))

							// 	fmt.Println()
							// }

							// send
							var err error
							fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
							addr := syscall.SockaddrInet4{
								Port: 6653,
								Addr: [4]byte{140, 120, 15, 183},
							}
							p := packet_byte[:save_len]
							err = syscall.Sendto(fd, p, 0, &addr)
							if err != nil {
								log.Fatal("Sendto:", err)
							}

						}
					}

				}

			}
		} else {
			// foword
		}
	}
}
