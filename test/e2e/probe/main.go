// The probe is an E2E fixture, not a networking installation component.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/dns/dnsmessage"
)

var outputMu sync.Mutex

func emit(v any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func event(kind, protocol, id, remote, digest string) {
	emit(map[string]any{"event": kind, "protocol": protocol, "id": id, "remote": remote, "digest": digest, "time": time.Now().UTC()})
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("serve|request|idle|pki required")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	if args[0] == "idle" {
		<-ctx.Done()
		return nil
	}
	if args[0] == "release" {
		return syscall.Kill(1, syscall.SIGTERM)
	}
	if args[0] == "pki" {
		dir := f.String("dir", "", "private output directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" {
			return errors.New("--dir required")
		}
		cert, key, err := certificate()
		if err != nil {
			return err
		}
		if err = os.MkdirAll(*dir, 0o700); err != nil {
			return err
		}
		for name, data := range map[string][]byte{"ca.pem": cert, "tls.crt": cert, "tls.key": key} {
			if err = os.WriteFile(filepath.Join(*dir, name), data, 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	if args[0] == "capture" {
		return capture(ctx, f, args[1:])
	}
	if args[0] == "serve" {
		return serve(ctx, f, args[1:])
	}
	if args[0] == "request" {
		return request(ctx, f, args[1:])
	}
	return fmt.Errorf("unknown command %q", args[0])
}

func certificate() ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "networking test origin"}, DNSNames: []string{"origin.test", "*.origin.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), nil
}

type packetLog struct{ net.PacketConn }

type sentPackets struct {
	net.PacketConn
	id string
}

func (p sentPackets) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := p.PacketConn.WriteTo(b, a)
	if err == nil {
		sum := sha256.Sum256(b[:n])
		event("sent", "quic", p.id, a.String(), hex.EncodeToString(sum[:]))
	}
	return n, err
}

func (p packetLog) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	if e == nil {
		sum := sha256.Sum256(b[:n])
		event("packet", "quic", "", a.String(), hex.EncodeToString(sum[:]))
	}
	return n, a, e
}

func serve(ctx context.Context, f *flag.FlagSet, args []string) error {
	httpPort := f.String("http", "", "HTTP listen port")
	httpsPort := f.String("https", "", "HTTPS listen port")
	tcpPort := f.String("tcp", "", "TCP echo listen port")
	udpPorts := f.String("udp", "", "comma separated UDP echo ports")
	quicPort := f.String("quic", "", "HTTP/3 listen port")
	dnsPort := f.String("dns", "", "UDP DNS listen port")
	certDir := f.String("cert-dir", "/certs", "private test certificates")
	if err := f.Parse(args); err != nil {
		return err
	}
	errCh := make(chan error, 16)
	start := func(protocol, port string, fn func() error) {
		event("ready", protocol, "", port, "")
		go func() { errCh <- fn() }()
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Networking-Test-Id")
		event("received", r.Proto, id, r.RemoteAddr, "")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id, "protocol": r.Proto})
	})
	for _, x := range []struct {
		port   string
		secure bool
	}{{*httpPort, false}, {*httpsPort, true}} {
		if x.port == "" {
			continue
		}
		l, err := net.Listen("tcp", ":"+x.port)
		if err != nil {
			return err
		}
		s := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ConnState: func(c net.Conn, state http.ConnState) {
			if state == http.StateNew {
				event("connection", "tcp", "", c.RemoteAddr().String(), "")
			}
		}}
		context.AfterFunc(ctx, func() { _ = s.Close() })
		if x.secure {
			start("https", x.port, func() error {
				return s.ServeTLS(l, filepath.Join(*certDir, "tls.crt"), filepath.Join(*certDir, "tls.key"))
			})
		} else {
			start("http", x.port, func() error { return s.Serve(l) })
		}
	}
	if *tcpPort != "" {
		l, err := net.Listen("tcp", ":"+*tcpPort)
		if err != nil {
			return err
		}
		context.AfterFunc(ctx, func() { _ = l.Close() })
		start("tcp", *tcpPort, func() error {
			for {
				c, err := l.Accept()
				if err != nil {
					return err
				}
				event("connection", "tcp", "", c.RemoteAddr().String(), "")
				go func() {
					defer c.Close()
					reader := bufio.NewScanner(c)
					for reader.Scan() {
						id := reader.Text()
						event("received", "tcp", id, c.RemoteAddr().String(), "")
						if _, err := fmt.Fprintln(c, id); err != nil {
							return
						}
					}
				}()
			}
		})
	}
	for port := range strings.SplitSeq(*udpPorts, ",") {
		if port == "" {
			continue
		}
		p, err := net.ListenPacket("udp", ":"+port)
		if err != nil {
			return err
		}
		context.AfterFunc(ctx, func() { _ = p.Close() })
		start("udp", port, func() error {
			b := make([]byte, 65535)
			for {
				n, a, err := p.ReadFrom(b)
				if err != nil {
					return err
				}
				sum := sha256.Sum256(b[:n])
				event("received", "udp", string(b[:n]), a.String(), hex.EncodeToString(sum[:]))
				if _, err = p.WriteTo(b[:n], a); err != nil {
					return err
				}
			}
		})
	}
	if *dnsPort != "" {
		p, err := net.ListenPacket("udp", ":"+*dnsPort)
		if err != nil {
			return err
		}
		context.AfterFunc(ctx, func() { _ = p.Close() })
		start("dns", *dnsPort, func() error {
			b := make([]byte, 4096)
			for {
				n, a, err := p.ReadFrom(b)
				if err != nil {
					return err
				}
				answer, err := dnsAnswer(b[:n], a.String())
				if err != nil {
					return err
				}
				if _, err = p.WriteTo(answer, a); err != nil {
					return err
				}
			}
		})
	}
	if *quicPort != "" {
		cert, err := tls.LoadX509KeyPair(filepath.Join(*certDir, "tls.crt"), filepath.Join(*certDir, "tls.key"))
		if err != nil {
			return err
		}
		p, err := net.ListenPacket("udp", ":"+*quicPort)
		if err != nil {
			return err
		}
		s := &http3.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}}
		context.AfterFunc(ctx, func() { _ = s.Close(); _ = p.Close() })
		start("quic", *quicPort, func() error { return s.Serve(packetLog{p}) })
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func dnsAnswer(data []byte, remote string) ([]byte, error) {
	var m dnsmessage.Message
	if err := m.Unpack(data); err != nil {
		return nil, err
	}
	if len(m.Questions) != 1 {
		return nil, errors.New("one question required")
	}
	q := m.Questions[0]
	id, _, _ := strings.Cut(q.Name.String(), ".")
	event("received", "dns", id, remote, "")
	m.Header.Response = true
	m.Header.Authoritative = true
	m.Header.RecursionAvailable = true
	m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
	return m.Pack()
}

type observation struct {
	ID        string    `json:"id"`
	Sequence  int       `json:"sequence"`
	Protocol  string    `json:"protocol"`
	Target    string    `json:"target"`
	Started   time.Time `json:"started"`
	Finished  time.Time `json:"finished"`
	Attempted bool      `json:"attempted"`
	Connected bool      `json:"connected"`
	Success   bool      `json:"success"`
	Local     string    `json:"local,omitempty"`
	Remote    string    `json:"remote,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	Response  string    `json:"response,omitempty"`
	Error     string    `json:"error,omitempty"`
}

func request(ctx context.Context, f *flag.FlagSet, args []string) error {
	protocol := f.String("protocol", "http", "http|https|tcp|udp|quic|dns-udp|dns-tcp|tls")
	target := f.String("target", "", "host:port")
	id := f.String("id", "", "correlation identifier")
	serverName := f.String("server-name", "origin.test", "TLS peer name")
	host := f.String("host", "", "HTTP Host override")
	ca := f.String("ca", "/trust/ca.pem", "trusted public CA")
	badCert := f.Bool("untrusted-client", false, "send self-signed fixture client certificate")
	peerURI := f.String("peer-uri", "", "verify this SPIFFE URI instead of a DNS SAN")
	query := f.String("query", "", "DNS name")
	duration := f.Duration("duration", 0, "continuous probe window")
	stopOnInput := f.Bool("stop-on-stdin", false, "stop between requests when stdin supplies the correlation ID; duration is the deadline")
	requiredSuccesses := f.Int("successes", 0, "stop after this many consecutive successes; duration is the deadline")
	interval := f.Duration("interval", 200*time.Millisecond, "continuous probe interval")
	timeout := f.Duration("timeout", 2*time.Second, "per-attempt deadline")
	persistent := f.Bool("persistent", false, "reuse TCP connection")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *target == "" || *id == "" || *interval <= 0 || *timeout <= 0 {
		return errors.New("target, id and positive interval/timeout required")
	}
	if *requiredSuccesses < 0 || (*stopOnInput || *requiredSuccesses > 0) && *duration <= 0 || *stopOnInput && *requiredSuccesses > 0 {
		return errors.New("controlled probes require a positive deadline and exactly one completion condition")
	}
	var stopInput <-chan error
	if *stopOnInput {
		input := os.Stdin
		defer input.Close()
		result := make(chan error, 1)
		stopInput = result
		go func() {
			line, err := bufio.NewReader(input).ReadString('\n')
			if err == nil && strings.TrimSpace(line) != *id {
				err = errors.New("probe stop identity mismatch")
			}
			result <- err
		}()
	}
	if !strings.Contains("|http|https|tcp|udp|quic|dns-udp|dns-tcp|tls|", "|"+*protocol+"|") {
		return errors.New("unsupported protocol")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: *serverName}
	if *protocol == "https" || *protocol == "quic" || *protocol == "tls" {
		b, err := os.ReadFile(*ca)
		if err != nil {
			return err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(b) {
			return errors.New("invalid CA")
		}
		if *peerURI != "" {
			// SPIFFE certificates use URI SANs. Replace DNS matching while retaining
			// full chain, expiry, usage and exact URI verification.
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("missing peer certificate")
				}
				intermediates := x509.NewCertPool()
				for _, c := range cs.PeerCertificates[1:] {
					intermediates.AddCert(c)
				}
				if _, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
					return err
				}
				for _, u := range cs.PeerCertificates[0].URIs {
					if u.String() == *peerURI {
						return nil
					}
				}
				return errors.New("unexpected SPIFFE identity")
			}
		}
		if *badCert {
			c, k, err := certificate()
			if err != nil {
				return err
			}
			pair, err := tls.X509KeyPair(c, k)
			if err != nil {
				return err
			}
			tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }
		}
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	h3 := &http3.Transport{TLSClientConfig: tlsConfig}
	defer h3.Close()
	if *protocol == "quic" {
		p, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			return err
		}
		qt := &quic.Transport{Conn: sentPackets{p, *id}}
		defer qt.Close()
		defer p.Close()
		h3.Dial = func(c context.Context, address string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			a, err := net.ResolveUDPAddr("udp", address)
			if err != nil {
				return nil, err
			}
			return qt.Dial(c, a, tc, qc)
		}
	}
	var connection net.Conn
	defer func() {
		if connection != nil {
			_ = connection.Close()
		}
	}()
	end := time.Now().Add(*duration)
	consecutiveSuccesses := 0
	finishInput := func(err error) error {
		if err != nil {
			return fmt.Errorf("probe control: %w", err)
		}
		event("probe-stopped", *protocol, *id, "", "")
		return nil
	}
	for sequence := 0; ; sequence++ {
		select {
		case err := <-stopInput:
			return finishInput(err)
		default:
		}
		cctx, cancel := context.WithTimeout(ctx, *timeout)
		o := observation{ID: *id, Sequence: sequence, Protocol: *protocol, Target: *target, Started: time.Now().UTC(), Attempted: true}
		err := func() error {
			if *protocol == "http" || *protocol == "https" || *protocol == "quic" {
				scheme := "http"
				if *protocol != "http" {
					scheme = "https"
				}
				req, err := http.NewRequestWithContext(cctx, http.MethodGet, scheme+"://"+*target+"/headers", nil)
				if err != nil {
					return err
				}
				if *host != "" {
					req.Host = *host
				}
				req.Header.Set("X-Networking-Test-Id", *id)
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
					o.Local = info.Conn.LocalAddr().String()
					o.Remote = info.Conn.RemoteAddr().String()
					o.Connected = true
				}}))
				var transport http.RoundTripper = tr
				if *protocol == "quic" {
					transport = h3
				}
				response, err := (&http.Client{Transport: transport}).Do(req)
				if err != nil {
					return err
				}
				defer response.Body.Close()
				o.Connected = true
				b, err := io.ReadAll(io.LimitReader(response.Body, 8192))
				if err != nil {
					return err
				}
				o.Response = string(b)
				var echoed struct {
					ID string `json:"id"`
				}
				if err = json.Unmarshal(b, &echoed); err != nil {
					return err
				}
				if response.StatusCode != 200 || echoed.ID != *id {
					return fmt.Errorf("unexpected application response %d", response.StatusCode)
				}
				return nil
			}
			network := "tcp"
			if *protocol == "udp" || *protocol == "dns-udp" {
				network = "udp"
			}
			var err error
			if connection == nil {
				if *protocol == "tls" {
					connection, err = (&tls.Dialer{Config: tlsConfig}).DialContext(cctx, "tcp", *target)
				} else {
					connection, err = (&net.Dialer{}).DialContext(cctx, network, *target)
				}
				if err != nil {
					return err
				}
			}
			c := connection
			o.Connected = true
			o.Local = c.LocalAddr().String()
			o.Remote = c.RemoteAddr().String()
			_ = c.SetDeadline(time.Now().Add(*timeout))
			payload := []byte(*id)
			if *protocol == "tcp" {
				payload = append(payload, '\n')
			}
			var dnsID uint16
			if strings.HasPrefix(*protocol, "dns-") {
				name := *query
				if name == "" {
					name = *id + ".test"
				}
				dn, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
				if err != nil {
					return err
				}
				var random [2]byte
				if _, err = rand.Read(random[:]); err != nil {
					return err
				}
				dnsID = binary.BigEndian.Uint16(random[:])
				m := dnsmessage.Message{Header: dnsmessage.Header{ID: dnsID, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dn, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
				payload, err = m.Pack()
				if err != nil {
					return err
				}
				if network == "tcp" {
					payload = append(binary.BigEndian.AppendUint16(nil, uint16(len(payload))), payload...)
				}
			}
			if *protocol == "tls" {
				payload = []byte("GET /headers HTTP/1.1\r\nHost: origin.test\r\nX-Networking-Test-Id: " + *id + "\r\nConnection: close\r\n\r\n")
			}
			sum := sha256.Sum256(payload)
			o.Digest = hex.EncodeToString(sum[:])
			if _, err = c.Write(payload); err != nil {
				return err
			}
			b := make([]byte, 8192)
			n, err := c.Read(b)
			if err != nil {
				return err
			}
			o.Response = string(b[:n])
			if strings.HasPrefix(*protocol, "dns-") {
				data := b[:n]
				if network == "tcp" {
					if n < 2 {
						return errors.New("short DNS frame")
					}
					size := int(binary.BigEndian.Uint16(data[:2]))
					data = data[2:]
					if len(data) < size {
						tail := make([]byte, size-len(data))
						if _, err = io.ReadFull(c, tail); err != nil {
							return err
						}
						data = append(data, tail...)
					}
				}
				var m dnsmessage.Message
				if err = m.Unpack(data); err != nil {
					return err
				}
				o.Response = fmt.Sprintf("dns_id=%d rcode=%s answers=%d", m.ID, m.RCode, len(m.Answers))
				if m.ID != dnsID || !m.Response || m.RCode != dnsmessage.RCodeSuccess {
					return errors.New("unexpected DNS response")
				}
				return nil
			}
			if *protocol == "tls" {
				if !strings.Contains(o.Response, *id) {
					return errors.New("no correlated application response")
				}
				return nil
			}
			if strings.TrimSpace(o.Response) != *id {
				return errors.New("echo identity mismatch")
			}
			return nil
		}()
		cancel()
		o.Finished = time.Now().UTC()
		o.Success = err == nil
		if err != nil {
			o.Error = err.Error()
		}
		emit(o)
		if o.Success {
			consecutiveSuccesses++
		} else {
			consecutiveSuccesses = 0
		}
		if connection != nil && (!*persistent || err != nil) {
			_ = connection.Close()
			connection = nil
		}
		if *requiredSuccesses > 0 && consecutiveSuccesses >= *requiredSuccesses {
			return nil
		}
		if time.Now().After(end) && (*stopOnInput || *requiredSuccesses > 0) {
			return errors.New("probe deadline exceeded before completion condition")
		}
		if *duration == 0 || time.Now().After(end) {
			return nil
		}
		select {
		case err := <-stopInput:
			return finishInput(err)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(*interval):
		}
	}
}
