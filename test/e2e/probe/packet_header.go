package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

func packetHeader(b []byte, port uint16) (map[string]any, bool) {
	if len(b) < 34 || binary.BigEndian.Uint16(b[12:14]) != 0x0800 {
		return nil, false
	}
	ip := b[14:]
	ihl := int(ip[0]&15) * 4
	if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+8 || binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 {
		return nil, false
	}
	transport := ip[ihl:]
	proto := ""
	sourcePort, destinationPort := binary.BigEndian.Uint16(transport[:2]), binary.BigEndian.Uint16(transport[2:4])
	switch ip[9] {
	case 6:
		proto = "tcp"
	case 17:
		proto = "udp"
	case 132:
		proto = "sctp"
	case 136:
		proto = "udplite"
	case 1:
		if transport[0] != 8 || transport[1] != 0 {
			return nil, false
		}
		proto = "icmp"
		sourcePort = binary.BigEndian.Uint16(transport[4:6])
		destinationPort = sourcePort
	default:
		return nil, false
	}
	if destinationPort != port {
		return nil, false
	}

	src, dst := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
	return map[string]any{"event": "network-packet", "protocol": proto, "remote": fmt.Sprintf("%s:%d", src, sourcePort), "destination": fmt.Sprintf("%s:%d", dst, port), "time": time.Now().UTC()}, true
}
