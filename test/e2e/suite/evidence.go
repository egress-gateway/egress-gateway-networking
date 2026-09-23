package suite

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	clientIdentity = "spiffe://cluster.local/ns/networking-test/sa/curl"
	serverIdentity = "spiffe://cluster.local/ns/networking-test/sa/httpbin"
	serviceCluster = "outbound|8000||httpbin.networking-test.svc.cluster.local"
)

type access struct {
	ID             string      `json:"test_id"`
	Code           json.Number `json:"code"`
	Method         string      `json:"method"`
	Path           string      `json:"path"`
	Cluster        string      `json:"upstream_cluster"`
	UpstreamTLS    string      `json:"upstream_tls"`
	UpstreamPeer   string      `json:"upstream_peer"`
	DownstreamTLS  string      `json:"downstream_tls"`
	DownstreamPeer string      `json:"downstream_peer"`
}

func findAccess(r io.Reader, id string) (access, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var a access
		if json.Unmarshal(scanner.Bytes(), &a) != nil || a.ID != id {
			continue
		}
		if a.Code.String() == "200" && a.Method == "GET" && a.Path == "/headers" {
			return a, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return access{}, err
	}
	return access{}, fmt.Errorf("no successful proxy evidence for request %s", id)
}

func checkMTLS(client, server access) error {
	validTLS := func(v string) bool { return v == "TLSv1.2" || v == "TLSv1.3" }
	if !validTLS(client.UpstreamTLS) || !validTLS(server.DownstreamTLS) {
		return errors.New("both directions must record an actual TLS session")
	}
	if client.UpstreamPeer != serverIdentity || server.DownstreamPeer != clientIdentity {
		return fmt.Errorf("unexpected peer identities: client sees %q, server sees %q", client.UpstreamPeer, server.DownstreamPeer)
	}
	return nil
}

func checkRejection(code string, rc, before, after int) error {
	if code != "000" || (rc != 52 && rc != 56) {
		return fmt.Errorf("expected empty/reset connection with no HTTP response, got HTTP %s curl exit %d", code, rc)
	}
	if after <= before {
		return fmt.Errorf("no server TLS filter-chain rejection: before=%d after=%d", before, after)
	}
	return nil
}

func rejectionCount(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var stats struct {
		Stats []struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		} `json:"stats"`
	}
	if err = json.Unmarshal(data, &stats); err != nil {
		return 0, err
	}
	for _, s := range stats.Stats {
		if s.Name == "listener.0.0.0.0_15006.downstream_cx_no_filter_chain_match" {
			return s.Value, nil
		}
	}
	return 0, errors.New("inbound TLS listener rejection counter missing")
}

func plaintextEvidence(dir string) error {
	read := func(name string) (string, error) {
		b, e := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b)), e
	}
	beforePod, err := read("server-before.json")
	if err != nil {
		return err
	}
	afterPod, err := read("server-after.json")
	if err != nil {
		return err
	}
	if beforePod != afterPod {
		return errors.New("server identity or restart count changed during rejection probe")
	}
	policy, err := read("authentication.json")
	if err != nil {
		return err
	}
	var auth struct {
		Mode string `json:"mode"`
	}
	if err = json.Unmarshal([]byte(policy), &auth); err != nil {
		return err
	}
	if auth.Mode != "STRICT" {
		return errors.New("server policy is not STRICT")
	}
	before, err := rejectionCount(filepath.Join(dir, "stats-before.json"))
	if err != nil {
		return err
	}
	after, err := rejectionCount(filepath.Join(dir, "stats-after.json"))
	if err != nil {
		return err
	}
	code, err := read("plaintext-code.txt")
	if err != nil {
		return err
	}
	exit, err := read("plaintext-exit.txt")
	if err != nil {
		return err
	}
	rc, err := strconv.Atoi(exit)
	if err != nil {
		return err
	}
	return checkRejection(code, rc, before, after)
}
