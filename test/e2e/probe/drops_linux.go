//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// traceDrops attaches an observational tracepoint, never a traffic hook. Kernel
// BTF supplies offsets on both CI's kernel and the local Docker VM's kernel.
// The BPF filter copies only IPv4/port headers for the owned receiver tuple.
func traceDrops(ctx context.Context, f *flag.FlagSet, args []string) error {
	target := f.String("target", "", "owned receiver IPv4:port")
	stop := f.String("stop-file", "", "finish when this owned file exists")
	stopNow := f.Bool("stop", false, "stop an existing observer")
	if err := f.Parse(args); err != nil {
		return err
	}
	address, err := netip.ParseAddrPort(*target)
	if err != nil || !address.Addr().Is4() || address.Port() == 0 || *stop == "" {
		return errors.New("drops requires an IPv4 target:port and stop-file")
	}
	if *stopNow {
		return os.WriteFile(*stop, nil, 0600)
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}
	offset := func(name, field string) (int32, error) {
		types, err := spec.AnyTypesByName(name)
		if err != nil {
			return 0, err
		}
		var found *int32
		for _, typ := range types {
			if n, ok := kernelFieldOffset(typ, field); ok {
				if found != nil && *found != n {
					return 0, fmt.Errorf("ambiguous kernel layout %s.%s", name, field)
				}
				found = new(n)
			}
		}
		if found != nil {
			return *found, nil
		}
		return 0, fmt.Errorf("missing kernel field %s.%s", name, field)
	}
	fields := [][2]string{{"trace_event_raw_kfree_skb", "skbaddr"}, {"trace_event_raw_kfree_skb", "reason"}, {"sk_buff", "head"}, {"sk_buff", "network_header"}, {"sk_buff", "dev"}, {"net_device", "ifindex"}}
	offsets := make([]int32, len(fields))
	for i, x := range fields {
		offsets[i], err = offset(x[0], x[1])
		if err != nil {
			return err
		}
	}
	var reasons *btf.Enum
	if err = spec.TypeByName("skb_drop_reason", &reasons); err != nil {
		return err
	}
	reason := int32(-1)
	for _, v := range reasons.Values {
		if v.Name == "SKB_DROP_REASON_NETFILTER_DROP" {
			reason = int32(v.Value)
		}
	}
	if reason < 0 {
		return errors.New("kernel has no NETFILTER_DROP reason")
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: "net_test_drops", Type: ebpf.RingBuf, MaxEntries: 256 * 1024})
	if err != nil {
		return err
	}
	defer events.Close()
	ip := address.Addr().As4()
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], address.Port())
	ins := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R1, asm.R6, int16(offsets[1]), asm.Word), asm.JNE.Imm(asm.R1, reason, "exit"), asm.LoadMem(asm.R7, asm.R6, int16(offsets[0]), asm.DWord)}
	read := func(dst int16, size int32, base asm.Register, offset int32) {
		ins = append(ins, asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, int32(dst)), asm.Mov.Imm(asm.R2, size), asm.Mov.Reg(asm.R3, base), asm.Add.Imm(asm.R3, offset), asm.FnProbeReadKernel.Call(), asm.JNE.Imm(asm.R0, 0, "exit"))
	}
	read(-8, 8, asm.R7, offsets[2])
	ins = append(ins, asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord))
	read(-8, 2, asm.R7, offsets[3])
	ins = append(ins, asm.LoadMem(asm.R9, asm.RFP, -8, asm.Half), asm.Add.Reg(asm.R8, asm.R9))
	read(-64, 20, asm.R8, 0)
	ins = append(ins, asm.LoadMem(asm.R1, asm.RFP, -64, asm.Byte), asm.And.Imm(asm.R1, 0xf0), asm.JNE.Imm(asm.R1, 0x40, "exit"), asm.LoadMem(asm.R1, asm.RFP, -48, asm.Word), asm.JNE.Imm(asm.R1, int32(binary.NativeEndian.Uint32(ip[:])), "exit"), asm.LoadMem(asm.R1, asm.RFP, -55, asm.Byte), asm.JEq.Imm(asm.R1, 6, "transport"), asm.JNE.Imm(asm.R1, 17, "exit"), asm.LoadMem(asm.R1, asm.RFP, -64, asm.Byte).WithSymbol("transport"), asm.And.Imm(asm.R1, 15), asm.LSh.Imm(asm.R1, 2), asm.Add.Reg(asm.R8, asm.R1))
	read(-44, 4, asm.R8, 0)
	ins = append(ins, asm.LoadMem(asm.R1, asm.RFP, -42, asm.Half), asm.JNE.Imm(asm.R1, int32(binary.NativeEndian.Uint16(port[:])), "exit"))
	read(-8, 8, asm.R7, offsets[4])
	ins = append(ins, asm.LoadMem(asm.R8, asm.RFP, -8, asm.DWord), asm.JEq.Imm(asm.R8, 0, "exit"))
	read(-40, 4, asm.R8, offsets[5])
	ins = append(ins, asm.StoreImm(asm.RFP, -36, int64(reason), asm.Word), asm.LoadMapPtr(asm.R1, events.FD()), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -64), asm.Mov.Imm(asm.R3, 32), asm.Mov.Imm(asm.R4, 0), asm.FnRingbufOutput.Call(), asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "net_test_drops", Type: ebpf.TracePoint, License: "GPL", Instructions: ins})
	if err != nil {
		return fmt.Errorf("drop observer: %w", err)
	}
	defer program.Close()
	attached, err := link.Tracepoint("skb", "kfree_skb", program, nil)
	if err != nil {
		return err
	}
	defer attached.Close()
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return err
	}
	defer reader.Close()
	emit(map[string]any{"event": "drops-ready", "target": address.String(), "reason": "NETFILTER_DROP"})
	ending := false
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !ending {
			if _, err := os.Stat(*stop); err == nil {
				if err := attached.Close(); err != nil {
					return err
				}
				ending = true
			}
		}
		reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
		r, err := reader.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if ending {
				emit(map[string]any{"event": "drops-complete"})
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		b := r.RawSample
		if len(b) != 32 {
			return errors.New("invalid drop observation size")
		}
		src, dst := netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		protocol := "tcp"
		if b[9] == 17 {
			protocol = "udp"
		}
		index := binary.NativeEndian.Uint32(b[24:28])
		device := ""
		if iface, e := net.InterfaceByIndex(int(index)); e == nil {
			device = iface.Name
		}
		emit(map[string]any{"event": "netfilter-drop", "protocol": protocol, "remote": net.JoinHostPort(src.String(), strconv.Itoa(int(binary.BigEndian.Uint16(b[20:22])))), "destination": net.JoinHostPort(dst.String(), strconv.Itoa(int(binary.BigEndian.Uint16(b[22:24])))), "interface": device, "ifindex": index, "reason": "NETFILTER_DROP", "time": time.Now().UTC()})
	}
}

func kernelFieldOffset(typ btf.Type, field string) (int32, bool) {
	var members []btf.Member
	switch st := typ.(type) {
	case *btf.Struct:
		members = st.Members
	case *btf.Union:
		members = st.Members
	default:
		return 0, false
	}
	for _, m := range members {
		if m.BitfieldSize != 0 {
			continue
		}
		if m.Name == field {
			return int32(m.Offset.Bytes()), true
		}
		if m.Name == "" {
			if n, ok := kernelFieldOffset(m.Type, field); ok {
				return int32(m.Offset.Bytes()) + n, true
			}
		}
	}
	return 0, false
}
