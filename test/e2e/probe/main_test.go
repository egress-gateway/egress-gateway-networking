package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func captureRequest(t *testing.T, args ...string) ([]observation, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "observations")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = previous; _ = f.Close() }()
	err = request(t.Context(), flag.NewFlagSet("request", flag.ContinueOnError), args)
	data, readErr := os.ReadFile(f.Name())
	if readErr != nil {
		t.Fatal(readErr)
	}
	var out []observation
	for line := range strings.SplitSeq(string(data), "\n") {
		var o observation
		if json.Unmarshal([]byte(line), &o) == nil && o.Attempted {
			out = append(out, o)
		}
	}
	return out, err
}

func TestActualHTTP3AndTrustedCertificate(t *testing.T) {
	cert, key, err := certificate()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			t.Error("not HTTP/3")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": r.Header.Get("X-Networking-Test-Id")})
	})}
	done := make(chan error, 1)
	go func() { done <- s.Serve(conn) }()
	t.Cleanup(func() { _ = s.Close(); _ = conn.Close(); <-done })
	out, err := captureRequest(t, "--protocol", "quic", "--target", conn.LocalAddr().String(), "--id", "quic-test", "--ca", ca)
	if err != nil || len(out) != 1 || !out[0].Success {
		t.Fatalf("HTTP/3 failed: %+v %v", out, err)
	}
	out, err = captureRequest(t, "--protocol", "quic", "--target", conn.LocalAddr().String(), "--id", "wrong-name", "--ca", ca, "--server-name", "untrusted.invalid")
	if err != nil || len(out) != 1 || out[0].Success {
		t.Fatalf("wrong TLS identity accepted: %+v %v", out, err)
	}
}

func TestQUICDoesNotFallBackToHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var httpCalls atomic.Int32
	s := &http.Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { httpCalls.Add(1) }), ReadHeaderTimeout: time.Second}
	go func() { _ = s.Serve(l) }()
	t.Cleanup(func() { _ = s.Close() })
	p, err := net.ListenPacket("udp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	cert, _, err := certificate()
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureRequest(t, "--protocol", "quic", "--target", l.Addr().String(), "--id", "forced-quic", "--ca", ca, "--timeout", "100ms")
	if err != nil || len(out) != 1 || out[0].Success || httpCalls.Load() != 0 {
		t.Fatalf("unexpected fallback: %+v %v calls=%d", out, err, httpCalls.Load())
	}
	_ = p.SetReadDeadline(time.Now().Add(time.Second))
	if n, _, err := p.ReadFrom(make([]byte, 2048)); err != nil || n == 0 {
		t.Fatalf("no actual QUIC packet: %d %v", n, err)
	}
}

func TestMissingTrustIsExecutionError(t *testing.T) {
	_, err := captureRequest(t, "--protocol", "https", "--target", "127.0.0.1:1", "--id", "bad-input", "--ca", filepath.Join(t.TempDir(), "missing.pem"))
	if err == nil {
		t.Fatal("missing CA became an expected network failure")
	}
	if err := run(context.Background(), []string{"unsupported"}); err == nil {
		t.Fatal("unknown operation accepted")
	}
}
