package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Reports only namespace networking and this process's privilege envelope.
func networkState(ctx context.Context, f *flag.FlagSet, args []string) error {
	id := f.String("id", "", "correlation identifier")
	ipv6 := f.Bool("attempt-ipv6", false, "observe IPv6 communication and loopback listener availability")
	idle := f.Bool("idle", false, "keep the application alive after first-execution observations")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("network-state id required")
	}
	started := time.Now().UTC()
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	addresses := map[string][]string{}
	sysctls := map[string]string{}
	names := []string{"all", "default"}
	for _, iface := range interfaces {
		values, err := iface.Addrs()
		if err != nil {
			return err
		}
		addresses[iface.Name] = []string{}
		for _, value := range values {
			addresses[iface.Name] = append(addresses[iface.Name], value.String())
		}
		names = append(names, iface.Name)
	}
	for _, name := range names {
		value, err := os.ReadFile(filepath.Join("/proc/sys/net/ipv6/conf", name, "disable_ipv6"))
		if errors.Is(err, os.ErrNotExist) {
			sysctls[name] = "unavailable"
			continue
		}
		if err != nil {
			return err
		}
		sysctls[name] = strings.TrimSpace(string(value))
	}
	files := map[string]string{}
	for _, name := range []string{"/proc/net/if_inet6", "/proc/net/ipv6_route", "/proc/sys/net/ipv4/ping_group_range"} {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		files[name] = string(data)
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	identity := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if key == "Uid" || key == "Gid" || strings.HasPrefix(key, "Cap") || key == "NoNewPrivs" || key == "Seccomp" {
			identity[key] = strings.TrimSpace(value)
		}
	}
	type socketResult struct {
		Family         int `json:"family"`
		Type           int `json:"type"`
		Protocol       int `json:"protocol"`
		ActualProtocol int `json:"actual_protocol"`
		Errno          int `json:"errno"`
	}
	results := make([]socketResult, 0, 2*6*256)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, typ := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_RAW, unix.SOCK_RDM, unix.SOCK_SEQPACKET, unix.SOCK_DCCP} {
			for protocol := range 256 {
				result := socketResult{Family: family, Type: typ, Protocol: protocol}
				fd, err := unix.Socket(family, typ|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, protocol)
				if err != nil {
					errno, ok := errors.AsType[unix.Errno](err)
					if !ok {
						return fmt.Errorf("socket inventory: %w", err)
					}
					result.Errno = int(errno)
				} else {
					result.ActualProtocol, err = unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
					unix.Close(fd)
					if err != nil {
						return err
					}
				}
				results = append(results, result)
			}
		}
	}
	emit(map[string]any{"id": *id, "event": "network-state", "started": started, "finished": time.Now().UTC(), "uid": os.Getuid(), "gid": os.Getgid(), "identity": identity, "addresses": addresses, "disable_ipv6": sysctls, "files": files, "sockets": results})
	if *ipv6 {
		for _, protocol := range []string{"tcp6", "udp6"} {
			for _, target := range []string{"[::1]:19091", "[fe80::ecee:eeff:feee:eeee%eth0]:19091"} {
				start := time.Now().UTC()
				c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, protocol, target)
				if err == nil {
					_ = c.SetWriteDeadline(time.Now().Add(time.Second))
					_, err = c.Write([]byte(*id))
					c.Close()
				}
				emitIPv6Attempt(*id, protocol, target, start, err)
			}
		}
		start := time.Now().UTC()
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err == nil {
			listener.Close()
		}
		emitIPv6Attempt(*id, "listen-tcp6", "[::1]:0", start, err)
	}
	if *idle {
		<-ctx.Done()
	}
	return nil
}

func emitIPv6Attempt(id, protocol, target string, started time.Time, err error) {
	errno := 0
	message := ""
	if err != nil {
		message = err.Error()
		if e, ok := errors.AsType[unix.Errno](err); ok {
			errno = int(e)
		}
	}
	emit(map[string]any{"id": id, "event": "ipv6-attempt", "uid": os.Getuid(), "protocol": protocol, "target": target, "started": started, "finished": time.Now().UTC(), "attempted": true, "success": err == nil, "socket_errno": errno, "error": message})
}
