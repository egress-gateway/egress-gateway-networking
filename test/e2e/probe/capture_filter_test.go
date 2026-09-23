package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

func TestCaptureFilterExcludesUnrelatedTraffic(t *testing.T) {
	vm, err := bpf.NewVM(captureFilter(9000))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		ether          uint16
		protocol       byte
		port, fragment uint16
		ihl            byte
		want           bool
	}{
		{"tcp", 0x800, 6, 9000, 0, 5, true},
		{"udp", 0x800, 17, 9000, 0, 5, true},
		{"IP options", 0x800, 6, 9000, 0, 6, true},
		{"API", 0x800, 6, 6443, 0, 5, false},
		{"ICMP", 0x800, 1, 9000, 0, 5, false},
		{"IPv6", 0x86dd, 6, 9000, 0, 5, false},
		{"fragment", 0x800, 6, 9000, 1, 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := make([]byte, 64)
			binary.BigEndian.PutUint16(packet[12:14], tc.ether)
			packet[14], packet[23] = 0x40|tc.ihl, tc.protocol
			binary.BigEndian.PutUint16(packet[20:22], tc.fragment)
			binary.BigEndian.PutUint16(packet[16+int(tc.ihl)*4:], tc.port)
			got, err := vm.Run(packet)
			if err != nil || (got > 0) != tc.want {
				t.Fatalf("filter=%d err=%v want=%t", got, err, tc.want)
			}
		})
	}
}
