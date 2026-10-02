package main

import "encoding/binary"

func icmpEcho(identifier uint16, payload []byte) []byte {
	packet := make([]byte, 8+len(payload))
	packet[0] = 8
	binary.BigEndian.PutUint16(packet[4:6], identifier)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	copy(packet[8:], payload)
	var sum uint32
	for i := 0; i < len(packet); i += 2 {
		sum += uint32(packet[i]) << 8
		if i+1 < len(packet) {
			sum += uint32(packet[i+1])
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[2:4], ^uint16(sum))
	return packet
}
