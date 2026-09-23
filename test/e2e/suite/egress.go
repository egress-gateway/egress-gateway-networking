package suite

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type probeRecord struct {
	UID           int       `json:"uid"`
	Dropped       *uint32   `json:"dropped"`
	KernelPackets *uint32   `json:"kernel_packets"`
	Captured      *uint32   `json:"captured"`
	Started       time.Time `json:"started"`
	Finished      time.Time `json:"finished"`
	Time          time.Time `json:"time"`
	ID            string    `json:"id"`
	Event         string    `json:"event"`
	Protocol      string    `json:"protocol"`
	Attempted     bool      `json:"attempted"`
	Connected     bool      `json:"connected"`
	Success       bool      `json:"success"`
	Local         string    `json:"local"`
	Remote        string    `json:"remote"`
	Destination   string    `json:"destination"`
	Interface     string    `json:"interface"`
	Reason        string    `json:"reason"`
	Digest        string    `json:"digest"`
	Error         string    `json:"error"`
}

func records(path string) ([]probeRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var results []probeRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var p probeRecord
		if err := json.Unmarshal(line, &p); err != nil {
			return nil, fmt.Errorf("%s:%d: invalid evidence record: %w", path, lineNumber, err)
		}
		results = append(results, p)
	}
	return results, scanner.Err()
}

type egressInputs struct {
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Client   string `json:"client"`
	Phase    string `json:"phase"`
}

func evaluateEgress(dir, id, contract string, expected egressInputs) (string, string, error) {
	for _, part := range []string{"before", "after"} {
		control, err := records(filepath.Join(dir, "control-"+part+".jsonl"))
		if err != nil {
			return "", "", err
		}
		valid := false
		for _, p := range control {
			if p.ID == id+"-control-"+part && p.Attempted && p.Success {
				valid = true
			}
		}
		if !valid {
			return ExecutionError, "independent receiver control failed " + part, nil
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "facts.json"))
	if err != nil {
		return "", "", err
	}
	var facts struct {
		egressInputs
		ID             string `json:"id"`
		FaultStart     string `json:"fault_start"`
		FaultEnd       string `json:"fault_end"`
		SourceIP       string `json:"source_ip"`
		FaultVerified  bool   `json:"fault_verified"`
		Restored       bool   `json:"restored"`
		ReceiverStable bool   `json:"receiver_stable"`
		StartupBlocked bool   `json:"startup_blocked"`
	}
	if err = json.Unmarshal(data, &facts); err != nil {
		return "", "", err
	}
	if id == "" || facts.ID != id || expected.Protocol == "" || expected.Target == "" || expected.Client == "" || expected.Phase == "" || facts.egressInputs != expected {
		return ExecutionError, "facts do not identify the current case attempt and requested inputs", nil
	}
	if !facts.Restored || !facts.ReceiverStable || !facts.FaultVerified {
		return ExecutionError, "fault, restoration or receiver identity was not verified", nil
	}
	needsWindow := expected.Phase != "healthy" && expected.Phase != "untrusted"
	var start, end time.Time
	if needsWindow {
		var e1, e2 error
		start, e1 = time.Parse(time.RFC3339, facts.FaultStart)
		end, e2 = time.Parse(time.RFC3339, facts.FaultEnd)
		if e1 != nil || e2 != nil || !end.After(start) {
			return ExecutionError, "invalid or missing fault observation window", nil
		}
	}
	if needsWindow && contract != "startup" {
		recovery, err := records(filepath.Join(dir, "recovery.jsonl"))
		if err != nil {
			return "", "", err
		}
		if err := validateRecovery(recovery, id+"-recovery", end, 2); err != nil {
			return ExecutionError, err.Error(), nil
		}
		if err := gatewayEvidence(dir, id+"-recovery", "http", recovery); err != nil {
			return Inconclusive, "recovery: " + err.Error(), nil
		}
	}
	if contract == "startup" {
		if !facts.StartupBlocked {
			return Violated, "application started before validated redirect/identity bootstrap", nil
		}
		recovered, err := records(filepath.Join(dir, "recovered.jsonl"))
		if err != nil {
			return "", "", err
		}
		if len(recovered) != 1 {
			return ExecutionError, "startup recovery must contain exactly one request", nil
		}
		if err := validateRecovery(recovered, id+"-recovered", end, 1); err != nil {
			return ExecutionError, err.Error(), nil
		}
		if err := gatewayEvidence(dir, id+"-recovered", "http", recovered); err != nil {
			return Inconclusive, err.Error(), nil
		}
		return Satisfied, "startup gate blocked execution; recovery obtained a fresh authenticated path", nil
	}
	probe, err := records(filepath.Join(dir, "probe.jsonl"))
	if err != nil {
		return "", "", err
	}
	receiver, err := records(filepath.Join(dir, "receiver.log"))
	if err != nil {
		return "", "", err
	}
	attempts, successes := 0, 0
	digests := map[string]bool{}
	for _, p := range probe {
		if p.ID != id {
			continue
		}
		if p.Attempted {
			attempts++
			if p.Success {
				successes++
			}
		}
		if p.Digest != "" {
			digests[p.Digest] = true
		}
	}
	if needsWindow {
		during, before := false, false
		connection := ""
		for _, p := range probe {
			if p.ID != id || !p.Attempted {
				continue
			}
			during = during || (!p.Started.Before(start) && !p.Started.After(end))
			before = before || p.Started.Before(start)
			if facts.Phase == "existing" && p.Success {
				if connection != "" && connection != p.Local {
					return Inconclusive, "existing stream silently reconnected", nil
				}
				connection = p.Local
			}
		}
		if !during || (facts.Phase == "existing" && (!before || connection == "")) {
			return Inconclusive, "no proven probes in the requested fault/connection window", nil
		}
	}
	if attempts == 0 {
		return Inconclusive, "no attributable probe attempts", nil
	}
	delivered := false
	for _, p := range receiver {
		if p.Event == "received" && p.ID == id || p.Event == "packet" && p.Digest != "" && digests[p.Digest] {
			delivered = true
		}
	}
	switch contract {
	case "deny":
		profile, _ := os.ReadFile(filepath.Join(dir, "profile"))
		calico := strings.TrimSpace(string(profile)) == "calico-istio"
		if calico && facts.Target == "node" && facts.SourceIP != "" {
			for _, p := range receiver {
				if (p.Event == "connection" || p.Event == "received") && peerIP(p.Remote) == facts.SourceIP {
					return Violated, "node listener accepted the forbidden source connection", nil
				}
			}
		}
		if delivered {
			if facts.Target == "external" && facts.Client == "workload" && facts.Phase == "healthy" && (facts.Protocol == "http" || facts.Protocol == "https") {
				if gatewayEvidence(dir, id, facts.Protocol, probe) == nil {
					return Satisfied, "direct-address attempt was governed by both authenticated proxies", nil
				}
				if err := directProxyEvidence(dir, id, facts.Protocol, probe); err != nil {
					return Inconclusive, err.Error(), nil
				}
				return Violated, "receiver delivery through workload Envoy bypassed the required gateway", nil
			}
			return Violated, "forbidden receiver delivery proved by correlation or packet digest", nil
		}
		if successes > 0 {
			return Inconclusive, "client succeeded without matching receiver evidence", nil
		}
		packets, err := records(filepath.Join(dir, "packets.jsonl"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return Inconclusive, "receiver packet observation missing", nil
			}
			return "", "", err
		}

		// The observer owns a complete case window. User-space read timestamps
		// cannot safely exclude a late packet after the client's deadline.
		for _, packet := range packets {
			if calico && facts.Target == "node" {
				continue
			} // AF_PACKET precedes the host INPUT filter.
			if packet.Event != "network-packet" {
				continue
			}
			for _, p := range probe {
				if p.ID == id && p.Attempted && (p.Local != "" && packet.Remote == p.Local || facts.SourceIP != "" && peerIP(packet.Remote) == facts.SourceIP) {
					return Violated, "receiver observed attributable connection packets despite failed application exchange", nil
				}
			}
		}
		ready, complete, lossless := false, false, false
		for _, p := range packets {
			ready = ready || p.Event == "capture-ready"
			if p.Event == "capture-complete" {
				complete = true
				lossless = p.Dropped != nil && *p.Dropped == 0 && p.KernelPackets != nil && p.Captured != nil && *p.KernelPackets == *p.Captured
			}
		}
		if !ready || !complete || !lossless {
			return Inconclusive, "receiver observation incomplete, dropped packets or left unread packets", nil
		}
		controls := map[string]bool{}
		for _, part := range []string{"before", "after"} {
			seen := false
			for _, r := range receiver {
				if r.ID != id+"-control-"+part || r.Remote == "" {
					continue
				}
				controls[r.Remote] = true
				for _, packet := range packets {
					seen = seen || packet.Event == "network-packet" && packet.Remote == r.Remote
				}
			}
			if !seen {
				return Inconclusive, "receiver capture did not observe positive control " + part, nil
			}
		}
		for _, packet := range packets {
			if packet.Event == "network-packet" && !controls[packet.Remote] {
				if calico && facts.Target == "node" && peerIP(packet.Remote) == facts.SourceIP {
					continue
				}
				if calico {
					background, err := gatewayBackgroundFlow(dir, id, facts.SourceIP, packet)
					if err != nil {
						return Inconclusive, "gateway NAT attribution invalid", err
					}
					if background {
						continue
					}
				}
				return Inconclusive, "unattributed receiver traffic prevents an isolation conclusion", nil
			}
		}
		if calico {
			if err := checkEnforcement(dir, id, facts.SourceIP); err != nil {
				return Inconclusive, err.Error(), nil
			}
		}
		return Satisfied, "bounded receiver packet observation proves no delivery; bracketing controls and stable receiver verified", nil
	case "allow":
		if successes == attempts {
			return Satisfied, "declared dependency returned a validated response", nil
		}
		return Violated, "declared dependency failed while independent controls worked", nil
	case "reject":
		if delivered || successes > 0 {
			return Violated, "unauthenticated or unexpected identity delivered an application request", nil
		}
		for _, file := range []string{"workload.log", "gateway.log"} {
			logs, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil {
				return "", "", err
			}
			for line := range strings.SplitSeq(string(logs), "\n") {
				var a struct {
					ID          string `json:"test_id"`
					Source      string `json:"source_ip"`
					Detail      string `json:"details"`
					Failure     string `json:"transport_failure"`
					DownFailure string `json:"downstream_failure"`
				}
				if json.Unmarshal([]byte(line), &a) != nil {
					continue
				}
				attributed := a.ID == id || facts.SourceIP != "" && a.Source == facts.SourceIP
				rejection := strings.Contains(a.Detail, "filter_chain_not_found") || strings.Contains(a.Detail, "rbac_access_denied") || strings.Contains(a.Failure, "CERTIFICATE_VERIFY_FAILED") || strings.Contains(a.Failure, "certificate") || strings.Contains(strings.ToLower(a.DownFailure), "certificate") || strings.Contains(a.DownFailure, "HTTP_REQUEST")
				if attributed && rejection {
					return Satisfied, "attributed TLS/identity rejection with no application delivery", nil
				}
			}
		}
		return Inconclusive, "no attributable server/proxy authentication rejection", nil
	case "gateway":
		if successes != attempts {
			return Violated, "authorized application path did not deliver all correlated requests", nil
		}
		if !delivered {
			return Inconclusive, "successful request is waiting for correlated receiver evidence", nil
		}
		if err := gatewayEvidence(dir, id, facts.Protocol, probe); err != nil {
			return Inconclusive, err.Error(), nil
		}
		return Satisfied, "receiver and both proxy hops correlate; expected mutual SPIFFE identities verified", nil
	default:
		return "", "", fmt.Errorf("unknown egress contract %q", contract)
	}
}

func validateRecovery(probes []probeRecord, id string, after time.Time, successes int) error {
	if len(probes) < successes {
		return errors.New("authenticated path recovery requests missing")
	}
	previous := after
	for _, p := range probes {
		if p.ID != id || !p.Attempted || p.Protocol != "http" || p.Started.IsZero() || p.Finished.Before(p.Started) || p.Started.Before(previous) {
			return errors.New("recovery evidence is incomplete, out of order or belongs to another case/window")
		}
		previous = p.Finished
	}
	for _, p := range probes[len(probes)-successes:] {
		if !p.Success {
			return errors.New("authenticated path did not recover")
		}
	}
	return nil
}

func gatewayEvidence(dir, id, protocol string, probes []probeRecord) error {
	return gatewayHostEvidence(dir, id, protocol, "gateway.networking-gateway.svc.cluster.local", probes)
}

func gatewayHostEvidence(dir, id, protocol, host string, probes []probeRecord) error {
	type hop struct {
		ID         string `json:"test_id"`
		Cluster    string `json:"upstream_cluster"`
		UpTLS      string `json:"upstream_tls"`
		UpPeer     string `json:"upstream_peer"`
		DownTLS    string `json:"downstream_tls"`
		DownPeer   string `json:"downstream_peer"`
		UpLocal    string `json:"upstream_local"`
		DownRemote string `json:"downstream_remote"`
	}
	read := func(name string) ([]hop, error) {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var out []hop
		for line := range strings.SplitSeq(string(data), "\n") {
			var h hop
			if json.Unmarshal([]byte(line), &h) == nil {
				out = append(out, h)
			}
		}
		return out, nil
	}
	client, err := read("workload.log")
	if err != nil {
		return err
	}
	gateway, err := read("gateway.log")
	if err != nil {
		return err
	}
	port := "15443"
	if protocol == "https" {
		port = "15444"
	}

	wanted, matched := 0, 0
	for _, p := range probes {
		if p.ID == id && p.Attempted && p.Success {
			wanted++
		}
	}
	used := map[int]bool{}
	for _, c := range client {
		match := c.ID == id
		if protocol == "https" {
			for _, p := range probes {
				if p.ID == id && p.Local != "" && p.Local == c.DownRemote {
					match = true
				}
			}
		}
		if !match {
			continue
		}
		if !strings.Contains(c.Cluster, "|"+port+"||"+host) || !validTLS(c.UpTLS) || c.UpPeer != "spiffe://cluster.local/ns/networking-gateway/sa/gateway" {
			return errors.New("a correlated request used an unexpected upstream path or identity")
		}
		paired := false
		for index, g := range gateway {
			if used[index] || c.UpLocal == "" || c.UpLocal != g.DownRemote || (protocol != "https" && g.ID != id) {
				continue
			}
			if !validTLS(g.DownTLS) || g.DownPeer != "spiffe://cluster.local/ns/networking-egress/sa/workload" {
				return errors.New("a correlated gateway request used an unexpected downstream identity")
			}
			used[index] = true
			paired = true
			break
		}
		if !paired {
			return errors.New("missing gateway observation for a correlated workload hop")
		}
		matched++
	}
	if matched == 0 || (protocol != "https" && matched != wanted) {
		return fmt.Errorf("incomplete proxy observations: %d matched hops for %d successful requests", matched, wanted)
	}
	return nil
}

func peerIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return host
}

func validTLS(version string) bool { return version == "TLSv1.2" || version == "TLSv1.3" }

func directProxyEvidence(dir, id, protocol string, probes []probeRecord) error {
	data, err := os.ReadFile(filepath.Join(dir, "workload.log"))
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		var hop struct {
			ID      string `json:"test_id"`
			Cluster string `json:"upstream_cluster"`
			Source  string `json:"downstream_remote"`
		}
		if json.Unmarshal([]byte(line), &hop) != nil {
			continue
		}
		matched := hop.ID == id
		if protocol == "https" {
			for _, p := range probes {
				matched = matched || (p.ID == id && p.Local != "" && hop.Source == p.Local)
			}
		}
		if matched && hop.Cluster != "" && hop.Cluster != "-" && !strings.Contains(hop.Cluster, "gateway.networking-gateway") {
			return nil
		}
	}
	return errors.New("receiver delivery lacks evidence of the claimed workload-only proxy path")
}
