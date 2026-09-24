//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestDropAddressComparisonInKernel(t *testing.T) {
	for _, last := range []byte{1, 127, 128, 200, 255} {
		ip := [4]byte{10, 244, 1, last}
		instructions := asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
			asm.LoadMem(asm.R3, asm.R1, 4, asm.Word),
			asm.Mov.Reg(asm.R4, asm.R2), asm.Add.Imm(asm.R4, 4),
			asm.JGT.Reg(asm.R4, asm.R3, "exit"),
			asm.LoadMem(asm.R1, asm.R2, 0, asm.Word),
			dropDestinationMismatch(ip),
			asm.Mov.Imm(asm.R0, 2), asm.Return(),
			asm.Mov.Imm(asm.R0, 1).WithSymbol("exit"), asm.Return(),
		}
		program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "drop_ip_test", Type: ebpf.XDP, License: "GPL", Instructions: instructions})
		if (errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)) && os.Getenv("REQUIRE_BPF_TEST") != "1" {
			t.Skip("kernel BPF permissions unavailable; run this test in the owned kind node")
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range []bool{true, false} {
			packet := make([]byte, 64)
			copy(packet, ip[:])
			want := uint32(2)
			if !match {
				packet[2]++
				want = 1
			}
			got, _, err := program.Test(packet)
			if err != nil || got != want {
				program.Close()
				t.Fatalf("last=%d match=%t got=%d want=%d err=%v", last, match, got, want, err)
			}
		}
		if err := program.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
