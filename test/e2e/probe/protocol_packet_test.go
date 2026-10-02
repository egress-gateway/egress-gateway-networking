package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

func TestProtocolObservationCorrelation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol byte
		icmp     bool
	}{
		{"sctp", 132, false}, {"udplite", 136, false}, {"icmp", 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vm, err := bpf.NewVM(captureFilter(9002))
			if err != nil {
				t.Fatal(err)
			}
			makePacket := func(port uint16) []byte {
				frame := make([]byte, 64)
				binary.BigEndian.PutUint16(frame[12:14], 0x800)
				frame[14], frame[23] = 0x45, tc.protocol
				copy(frame[26:30], []byte{10, 0, 0, 1})
				copy(frame[30:34], []byte{10, 0, 0, 2})
				binary.BigEndian.PutUint16(frame[34:36], 45000)
				binary.BigEndian.PutUint16(frame[36:38], port)
				if tc.icmp {
					copy(frame[34:], icmpEcho(port, []byte("case")))
				}
				return frame
			}
			for _, port := range []uint16{9002, 9003} {
				frame := makePacket(port)
				n, err := vm.Run(frame)
				if err != nil {
					t.Fatal(err)
				}
				packet, ok := packetHeader(frame, 9002)
				if (n > 0) != (port == 9002) || ok != (port == 9002) {
					t.Fatalf("wrong filter/header decision: %d %+v", n, packet)
				}
				if ok && (packet["protocol"] != tc.name || packet["destination"] != "10.0.0.2:9002") {
					t.Fatalf("wrong association: %+v", packet)
				}
				if ok {
					want := "10.0.0.1:45000"
					if tc.icmp {
						want = "10.0.0.1:9002"
					}
					if packet["remote"] != want {
						t.Fatalf("source association: %+v", packet)
					}
				}
			}
			fragmented := makePacket(9002)
			binary.BigEndian.PutUint16(fragmented[20:22], 1)
			n, err := vm.Run(fragmented)
			if err != nil || n != 0 {
				t.Fatalf("noninitial fragment accepted: %d %v", n, err)
			}
			if _, ok := packetHeader(fragmented, 9002); ok {
				t.Fatal("noninitial fragment has no attributable transport header")
			}
			if tc.icmp {
				reply := makePacket(9002)
				reply[34] = 0
				n, _ := vm.Run(reply)
				if n != 0 {
					t.Fatal("echo reply counted as target request")
				}
			}
		})
	}
}

func TestICMPEchoChecksum(t *testing.T) {
	for _, payload := range []string{"even", "odd"} {
		packet := icmpEcho(9004, []byte(payload))
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
		if sum != 0xffff || packet[0] != 8 || binary.BigEndian.Uint16(packet[4:6]) != 9004 || string(packet[8:]) != payload {
			t.Fatalf("uncorrelated or invalid echo: %x", packet)
		}
	}
}
