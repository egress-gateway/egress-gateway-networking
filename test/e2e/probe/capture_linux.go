//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Capture emits only IPv4 TCP/UDP headers. It runs in an owned receiver network
// namespace, never in the unprivileged application under test.
func capture(ctx context.Context, f *flag.FlagSet, args []string) error {
	port := f.Int("port", 0, "destination port")
	stopNow := f.Bool("stop", false, "finish an existing capture")
	stop := f.String("stop-file", "", "stop when this owned file exists")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 || *stop == "" {
		return errors.New("capture requires port and stop-file")
	}
	if *stopNow {
		return os.WriteFile(*stop, nil, 0600)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	compiled, err := bpf.Assemble(captureFilter(uint16(*port)))
	if err != nil {
		return err
	}
	filter := make([]unix.SockFilter, len(compiled))
	for i, instruction := range compiled {
		filter[i] = unix.SockFilter{Code: instruction.Op, Jt: instruction.Jt, Jf: instruction.Jf, K: instruction.K}
	}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); err != nil {
		return err
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}); err != nil {
		return err
	}
	emit(map[string]any{"event": "capture-ready", "port": *port})
	b := make([]byte, 65536)
	var captured uint32
	var draining time.Time
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if draining.IsZero() {
			if _, err := os.Stat(*stop); err == nil {
				draining = time.Now()
			}
		}
		flags := 0
		if !draining.IsZero() {
			if time.Since(draining) > 2*time.Second {
				return errors.New("receiver capture queue did not drain")
			}
			flags = unix.MSG_DONTWAIT
		}
		n, _, err := unix.Recvfrom(fd, b, flags)
		if errors.Is(err, unix.EAGAIN) && !draining.IsZero() {
			stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
			if err != nil {
				return err
			}
			emit(map[string]any{"event": "capture-complete", "dropped": stats.Drops, "kernel_packets": stats.Packets, "captured": captured})
			return nil
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		captured++
		packet, ok := packetHeader(b[:n], uint16(*port))
		if ok {
			emit(packet)
		}
	}
}

func htons(n uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], n)
	return binary.NativeEndian.Uint16(b[:])
}

func packetHeader(b []byte, port uint16) (map[string]any, bool) {
	if len(b) < 34 || binary.BigEndian.Uint16(b[12:14]) != unix.ETH_P_IP {
		return nil, false
	}
	ip := b[14:]
	ihl := int(ip[0]&15) * 4
	if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+8 || binary.BigEndian.Uint16(ip[6:8])&0x1fff != 0 {
		return nil, false
	}
	proto := "tcp"
	if ip[9] == 17 {
		proto = "udp"
	} else if ip[9] != 6 {
		return nil, false
	}
	transport := ip[ihl:]
	if binary.BigEndian.Uint16(transport[2:4]) != port {
		return nil, false
	}
	src, dst := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
	return map[string]any{"event": "network-packet", "protocol": proto, "remote": fmt.Sprintf("%s:%d", src, binary.BigEndian.Uint16(transport[:2])), "destination": fmt.Sprintf("%s:%d", dst, port), "time": time.Now().UTC()}, true
}
