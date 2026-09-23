package suite

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	clientIdentity = "spiffe://cluster.local/ns/networking-test/sa/curl"
	serverIdentity = "spiffe://cluster.local/ns/networking-test/sa/httpbin"
	serviceCluster = "outbound|8000||httpbin.networking-test.svc.cluster.local;"
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
	SourceIP       string      `json:"source_ip"`
	Details        string      `json:"details"`
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

func checkRejection(code string, rc int, serverRejected bool) error {
	if code != "000" || (rc != 52 && rc != 56) {
		return fmt.Errorf("expected empty/reset connection with no HTTP response, got HTTP %s curl exit %d", code, rc)
	}
	if !serverRejected {
		return errors.New("no server TLS filter-chain rejection for this client")
	}
	return nil
}

func findRejection(r io.Reader, ip string) (bool, error) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return false, err
	}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		var a access
		if json.Unmarshal(scanner.Bytes(), &a) != nil {
			continue
		}
		if a.SourceIP == ip && a.Details == "filter_chain_not_found" && a.Code.String() == "0" && a.DownstreamTLS == "" {
			return true, nil
		}
	}
	return false, scanner.Err()
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
	client, err := read("plaintext-client.json")
	if err != nil {
		return err
	}
	var source struct {
		IP string `json:"ip"`
	}
	if err = json.Unmarshal([]byte(client), &source); err != nil {
		return err
	}
	logs, err := os.Open(filepath.Join(dir, "rejections.log"))
	if err != nil {
		return err
	}
	defer logs.Close()
	rejected, err := findRejection(logs, source.IP)
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
	return checkRejection(code, rc, rejected)
}
