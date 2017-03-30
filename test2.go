package main

import (
	"encoding/binary"
	"fmt"
	//"github.com/aven725/ofp4"
	"github.com/google/gopacket"
)

// Create OpenFlow layer structure
type OpenFlowLayer struct {
	// This layer just has two bytes at the front
	oft_version uint8
	ofp_type    byte
	ofp_lenght  uint16
	ofp_xid     uint32
	ofp_payload []byte
}

// Register the layer type so we can use it
// The first argument is an ID. Use negative
// or 2000+ for custom layers. It must be unique
var OpenFlowLayerType = gopacket.RegisterLayerType(
	2002,
	gopacket.LayerTypeMetadata{
		"OpenFlowLayerType",
		gopacket.DecodeFunc(decodeOpenFlowLayer),
	},
)

// LayerContents returns the information that our layer
// provides. In this case it is a header layer so
// we return the header information
func (l OpenFlowLayer) LayerContents() []byte {
	return l.ofp_payload
}

// LayerPayload returns the subsequent layer built
// on top of our layer or raw payload
func (l OpenFlowLayer) LayerXid() uint32 {
	return l.ofp_xid
}

func (l OpenFlowLayer) LayerPayload() []byte {
	//return l.ofp_payload
	return l.ofp_payload
}

func (l OpenFlowLayer) LayerType() gopacket.LayerType {
	return OpenFlowLayerType
}

func (l OpenFlowLayer) LayerVersion() uint8 {
	return l.oft_version
}

// Custom decode function. We can name it whatever we want
// but it should have the same arguments and return value
// When the layer is registered we tell it to use this decode function
func decodeOpenFlowLayer(data []byte, p gopacket.PacketBuilder) error {
	// AddLayer appends to the list of layers that the packet has
	p.AddLayer(&OpenFlowLayer{uint8(data[0]), data[1], binary.BigEndian.Uint16(data[2:3]), binary.BigEndian.Uint32(data[4:7]), data[8:]})

	// The return value tells the packet what layer to expect
	// with the rest of the data. It could be another header layer,
	// nothing, or a payload layer.

	// nil means this is the last layer. No more decoding
	// return nil

	// Returning another layer type tells it to decode
	// the next layer with that layer's decoder function
	// return p.NextDecoder(layers.LayerTypeEthernet)

	// Returning payload type means the rest of the data
	// is raw payload. It will set the application layer
	// contents with the payload
	return p.NextDecoder(gopacket.LayerTypePayload)
}

func main() {
	// If you create your own encoding and decoding you can essentially
	// create your own protocol or implement a protocol that is not
	// already defined in the layers package. In our example we are just
	// wrapping a normal ethernet packet with our own layer.
	// Creating your own protocol is good if you want to create
	// some obfuscated binary data type that was difficult for others
	// to decode

	// Finally, decode your packets:
	rawBytes := []byte{0x88, 0x5a, 0x92, 0x9a, 0x6c, 0x50, 0x38, 0xd5, 0x47, 0x11, 0x31, 0x63, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0x14, 0x9e, 0x40, 0x00, 0x80, 0x06, 0xc1, 0xa0, 0x8c, 0x78, 0x0f, 0xb7, 0xd2, 0x3d, 0xb6, 0x24, 0x04, 0x0a, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x12, 0x14, 12, 34, 51}
	packet := gopacket.NewPacket(
		rawBytes,
		OpenFlowLayerType,
		gopacket.Default,
	)
	fmt.Println("Created packet out of raw bytes.")
	fmt.Println(packet.Data())

	// Decode the packet as our custom layer
	customLayer := packet.Layer(OpenFlowLayerType)
	if customLayer != nil {
		fmt.Println("Packet was successfully decoded with custom layer decoder.")
		customLayerContent, _ := customLayer.(*OpenFlowLayer)
		// Now we can access the elements of the custom struct
		fmt.Println("Payload: ", customLayerContent.LayerPayload())
		fmt.Println("customLayerContent:", customLayerContent.LayerContents())
		fmt.Println("AnotherByte element:", customLayerContent.LayerVersion())
	} else {
		fmt.Println("Error", customLayer)
	}
}
