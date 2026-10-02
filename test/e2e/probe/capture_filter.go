package main

import "golang.org/x/net/bpf"

// ICMP echo uses the identifier in place of a port in the private observation
// tuple. All other accepted protocols share the first two transport port fields.
func captureFilter(port uint16) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipFalse: 16},
		bpf.LoadAbsolute{Off: 20, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 14},
		bpf.LoadMemShift{Off: 14},
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 6, SkipTrue: 8},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 7},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 132, SkipTrue: 6},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 136, SkipTrue: 5},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1, SkipFalse: 7},
		bpf.LoadIndirect{Off: 14, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 8, SkipFalse: 5},
		bpf.LoadIndirect{Off: 18, Size: 2},
		bpf.Jump{Skip: 1},
		bpf.LoadIndirect{Off: 16, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(port), SkipFalse: 1},
		bpf.RetConstant{Val: 65535},
		bpf.RetConstant{Val: 0},
	}
}
