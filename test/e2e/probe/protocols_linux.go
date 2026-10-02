package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func protocolSocket(protocol string) (int, error) {
	typ, number := unix.SOCK_DGRAM, 0
	switch protocol {
	case "tcp":
		typ, number = unix.SOCK_STREAM, unix.IPPROTO_TCP
	case "sctp":
		typ, number = unix.SOCK_STREAM, unix.IPPROTO_SCTP
	case "udplite":
		number = unix.IPPROTO_UDPLITE
	case "icmp":
		number = unix.IPPROTO_ICMP
	default:
		return -1, fmt.Errorf("unknown socket protocol %q", protocol)
	}
	return unix.Socket(unix.AF_INET, typ|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, number)
}

func socketReady(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		wait := 100
		if deadline, ok := ctx.Deadline(); ok {
			wait = max(1, min(wait, int(time.Until(deadline).Milliseconds())))
		}
		p := []unix.PollFd{{Fd: int32(fd), Events: events}}
		n, err := unix.Poll(p, wait)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if p[0].Revents&unix.POLLNVAL != 0 {
				return unix.EBADF
			}
			return nil
		}
	}
}

func socketAddress(address unix.Sockaddr) (string, error) {
	a, ok := address.(*unix.SockaddrInet4)
	if !ok {
		return "", errors.New("expected IPv4 socket address")
	}
	return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port)).String(), nil
}

func protocolRequest(ctx context.Context, o *observation) error {
	target, err := netip.ParseAddrPort(o.Target)
	if err != nil || !target.Addr().Is4() || target.Port() == 0 {
		return errors.New("protocol probe needs an IPv4 address and port (echo identifier for ICMP)")
	}
	fd, err := protocolSocket(o.Protocol)
	if err != nil {
		if errno, ok := errors.AsType[unix.Errno](err); ok {
			o.SocketError = int(errno)
		}
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)
	remote := &unix.SockaddrInet4{Addr: target.Addr().As4(), Port: int(target.Port())}
	if o.Protocol == "icmp" {
		// A ping socket uses its bound port as the kernel-assigned echo identifier.
		if err = unix.Bind(fd, &unix.SockaddrInet4{Port: int(target.Port())}); err != nil {
			return err
		}
		remote.Port = 0
	}
	connectErr := unix.Connect(fd, remote)
	local, err := unix.Getsockname(fd)
	if err != nil {
		return err
	}
	o.Local, err = socketAddress(local)
	if err != nil {
		return err
	}
	o.Remote = target.String()
	if errors.Is(connectErr, unix.EINPROGRESS) {
		if err = socketReady(ctx, fd, unix.POLLOUT); err != nil {
			return err
		}
		errno, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if e != nil {
			return e
		}
		if errno != 0 {
			return unix.Errno(errno)
		}
	} else if connectErr != nil {
		return connectErr
	}
	o.Connected = true
	if o.Protocol == "tcp" {
		return nil
	}
	data := []byte(o.ID)
	if o.Protocol == "icmp" {
		data = icmpEcho(target.Port(), data)
	}
	if err = socketReady(ctx, fd, unix.POLLOUT); err != nil {
		return err
	}
	n, err := unix.Write(fd, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	sum := sha256.Sum256(data)
	o.Digest = hex.EncodeToString(sum[:])
	event("sent", o.Protocol, o.ID, o.Local, o.Digest)
	if err = socketReady(ctx, fd, unix.POLLIN); err != nil {
		return err
	}
	reply := make([]byte, 4096)
	n, err = unix.Read(fd, reply)
	if err != nil {
		return err
	}
	reply = reply[:n]
	if o.Protocol == "icmp" {
		if len(reply) < 8 || reply[0] != 0 || reply[1] != 0 || binary.BigEndian.Uint16(reply[4:6]) != target.Port() {
			return errors.New("unexpected ICMP echo reply")
		}
		reply = reply[8:]
	}
	if !bytes.Equal(reply, []byte(o.ID)) {
		return errors.New("uncorrelated protocol echo")
	}
	o.Response = string(reply)
	return nil
}

func protocolListener(ctx context.Context, protocol, port string) (func() error, error) {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return nil, errors.New("invalid protocol listener port")
	}
	fd, err := protocolSocket(protocol)
	if err != nil {
		return nil, err
	}
	if err = unix.Bind(fd, &unix.SockaddrInet4{Port: number}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if protocol == "sctp" {
		if err = unix.Listen(fd, 16); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	return func() error {
		defer unix.Close(fd)
		for {
			if err := socketReady(ctx, fd, unix.POLLIN); err != nil {
				return err
			}
			if protocol == "sctp" {
				client, peer, err := unix.Accept4(fd, unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC)
				if errors.Is(err, unix.EAGAIN) {
					continue
				}
				if err != nil {
					return err
				}
				remote, err := socketAddress(peer)
				if err != nil {
					unix.Close(client)
					return err
				}
				event("connection", protocol, "", remote, "")
				err = func() error {
					defer unix.Close(client)
					cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					if err := socketReady(cctx, client, unix.POLLIN); err != nil {
						return err
					}
					data := make([]byte, 4096)
					n, err := unix.Read(client, data)
					if err != nil {
						return err
					}
					if n == 0 {
						return nil
					}
					event("received", protocol, string(data[:n]), remote, "")
					if err = socketReady(cctx, client, unix.POLLOUT); err != nil {
						return err
					}
					sent, err := unix.Write(client, data[:n])
					if err == nil && sent != n {
						return io.ErrShortWrite
					}
					return err
				}()
				if err != nil {
					event("connection-error", protocol, "", remote, err.Error())
				}
			} else {
				data := make([]byte, 4096)
				n, peer, err := unix.Recvfrom(fd, data, 0)
				if errors.Is(err, unix.EAGAIN) {
					continue
				}
				if err != nil {
					return err
				}
				remote, err := socketAddress(peer)
				if err != nil {
					return err
				}
				sum := sha256.Sum256(data[:n])
				event("received", protocol, string(data[:n]), remote, hex.EncodeToString(sum[:]))
				if err = unix.Sendto(fd, data[:n], 0, peer); err != nil {
					return err
				}
			}
		}
	}, nil
}
