package suite

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type dnsFacts struct {
	ID            string   `json:"id"`
	Mode          string   `json:"mode"`
	Name          string   `json:"name"`
	Source        string   `json:"source"`
	Transport     string   `json:"transport"`
	Type          uint16   `json:"type"`
	Restored      bool     `json:"restored"`
	FaultVerified bool     `json:"fault_verified"`
	Ready         bool     `json:"ready"`
	Controls      []string `json:"controls"`
	Captures      []string `json:"captures"`
	DropFiles     []string `json:"drop_files"`
	Dependency    string   `json:"dependency,omitempty"`
	Attempted     bool     `json:"attempted"`
	Functional    bool     `json:"functional"`
	Detail        string   `json:"detail"`
}

type dnsExchange struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       uint16   `json:"type"`
	Transport  string   `json:"transport"`
	Attempted  bool     `json:"attempted"`
	Sent       bool     `json:"sent"`
	Received   bool     `json:"received"`
	Correlated bool     `json:"correlated"`
	RCODE      string   `json:"rcode"`
	Answers    []string `json:"answers"`
	Error      string   `json:"error"`
}

func readDNSJSON(dir, name string, v any) error {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Functionality is separate from network isolation: a blocked recursive lookup
// never proves that local synthesis works.
func evaluateDNS(dir, id string) (actual, functionality, reason string, err error) {
	var f dnsFacts
	if err = readDNSJSON(dir, "dns-facts.json", &f); err != nil {
		return ExecutionError, "not_evaluated", "missing experiment facts", err
	}
	if f.ID != id {
		return ExecutionError, "not_evaluated", "case identity mismatch", errors.New("DNS case identity mismatch")
	}
	if f.Dependency != "" {
		return NotRun, "not_evaluated", f.Dependency, nil
	}
	defer func() {
		if actual != Satisfied {
			return
		}
		if dnsNeedsRecovery(f.Mode) {
			var recovered dnsExchange
			if e := readDNSJSON(dir, "recovery.json", &recovered); e != nil || recovered.ID != id+"-recovery" || !recovered.Correlated || recovered.RCODE != "RCodeSuccess" || len(recovered.Answers) == 0 {
				actual, reason, err = ExecutionError, "local resolution did not recover", errors.New("DNS recovery positive control failed")
				return
			}
			state, _, detail, e := evaluateDNS(filepath.Join(dir, "recovery-isolation"), id+"-recovery-isolation")
			if e != nil || state != Satisfied {
				actual, reason, err = ExecutionError, "recovery isolation failed: "+detail, errors.New("DNS deny did not recover")
				return
			}
		}
	}()
	if !f.Restored || !f.FaultVerified {
		return ExecutionError, "not_evaluated", "fault or recovery unverified", errors.New("DNS fault/recovery incomplete")
	}
	if _, e := netip.ParseAddr(f.Source); e != nil {
		return Inconclusive, "not_evaluated", "missing source endpoint", nil
	}
	if !f.Attempted {
		return ExecutionError, "not_evaluated", "probe not executed", errors.New("DNS experiment did not execute")
	}
	var tuple struct {
		Source    string   `json:"source"`
		Endpoints []string `json:"endpoints"`
		External  string   `json:"external"`
	}
	if e := readDNSJSON(dir, "dns-tuples.json", &tuple); e != nil || tuple.Source != f.Source {
		return Inconclusive, "not_evaluated", "missing endpoint/NAT mapping", nil
	}
	if len(f.Controls) < 2 || len(f.Captures) < 2 {
		return Inconclusive, "not_evaluated", "missing controls or complete observation", nil
	}
	for _, name := range f.Controls {
		var c dnsExchange
		if e := readDNSJSON(dir, name, &c); e != nil {
			return Inconclusive, "not_evaluated", e.Error(), nil
		}
		if c.ID != id+"-control" || !c.Sent || !c.Received || !c.Correlated || c.RCODE != "RCodeSuccess" || len(c.Answers) == 0 {
			return ExecutionError, "not_evaluated", "receiver health control failed", errors.New("DNS receiver not healthy")
		}
	}
	attempts, arrivals := 0, 0
	nat, _ := os.ReadFile(filepath.Join(dir, "conntrack.txt"))
	for _, name := range f.Captures {
		packets, e := records(filepath.Join(dir, name))
		if e != nil {
			return Inconclusive, "not_evaluated", e.Error(), nil
		}
		if e = completeCapture(packets); e != nil {
			return Inconclusive, "not_evaluated", e.Error(), nil
		}
		for _, p := range packets {
			owned := peerIP(p.Remote) == f.Source || dnsNATOwner(string(nat), f.Source, p.Remote, p.Destination)
			if p.Event == "network-packet" && name == "receiver-external.jsonl" && !owned {
				return Inconclusive, "not_evaluated", "unattributed external receiver packet; NAT ownership is unresolved", nil
			}
			if p.Event == "network-packet" && owned {
				if strings.HasPrefix(name, "source-") {
					attempts++
				} else {
					arrivals++
				}
			}
		}
	}
	if arrivals > 0 {
		return Violated, "not_evaluated", "protected source reached a forbidden DNS receiver", nil
	}
	if attempts > 0 {
		matched := false
		for _, name := range f.DropFiles {
			ps, e := records(filepath.Join(dir, name))
			if e != nil {
				return Inconclusive, "not_evaluated", e.Error(), nil
			}
			ready, done := false, false
			for _, p := range ps {
				ready = ready || p.Event == "drops-ready"
				done = done || p.Event == "drops-complete"
				if p.Event == "netfilter-drop" && peerIP(p.Remote) == f.Source && p.Reason == "NETFILTER_DROP" && strings.HasPrefix(p.Interface, "cali") {
					for _, ip := range append(tuple.Endpoints, tuple.External) {
						if p.Destination == ip+":53" {
							matched = true
						}
					}
				}
			}
			if !ready || !done {
				return Inconclusive, "not_evaluated", "incomplete enforcement observation", nil
			}
		}
		if !matched {
			return Inconclusive, "not_evaluated", "upstream attempt has no associated Calico drop", nil
		}
	}
	functionality = "satisfied"
	switch f.Mode {
	case "capture-off-tcp", "proxy-uid-tcp", "sidecar-stopped-tcp":
		actual, reason, err = dnsForbiddenTCP(dir, id, f, tuple.External, string(nat))
		return actual, "observed", reason, err
	}
	if strings.HasPrefix(f.Mode, "bootstrap-") {
		var pod struct {
			Status struct {
				Conditions []struct {
					Type   string `json:"type"`
					Status string `json:"status"`
				} `json:"conditions"`
			} `json:"status"`
		}
		if e := readDNSJSON(dir, "pod-after.json", &pod); e != nil {
			return Inconclusive, "not_evaluated", e.Error(), nil
		}
		f.Functional = false
		for _, c := range pod.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				f.Functional = true
			}
		}
		if f.Functional {
			var certs struct {
				Certificates []json.RawMessage `json:"certificates"`
			}
			if e := readDNSJSON(dir, "certificates.json", &certs); e != nil || len(certs.Certificates) == 0 {
				return Inconclusive, "not_evaluated", "bootstrap has no loaded certificate evidence", nil
			}
		}
	}
	if strings.HasPrefix(f.Mode, "http-") || strings.HasPrefix(f.Mode, "https-") || f.Mode == "raw-tcp" || f.Mode == "stale-vip" || f.Mode == "restart" || f.Mode == "recreate" {
		f.Functional, err = dnsApplication(dir, id, f)
		if err != nil {
			return Inconclusive, "not_evaluated", err.Error(), nil
		}
	}
	if strings.HasPrefix(f.Mode, "bootstrap-") || f.Mode == "restart" || f.Mode == "recreate" || f.Mode == "stale-vip" || strings.HasPrefix(f.Mode, "http-") || strings.HasPrefix(f.Mode, "https-") || f.Mode == "raw-tcp" {
		if !f.Functional {
			functionality = "not_satisfied"
		}
	} else {
		var q dnsExchange
		if e := readDNSJSON(dir, "query.json", &q); e != nil {
			return ExecutionError, "not_evaluated", e.Error(), e
		}
		if q.ID != id || q.Name != f.Name || q.Type != f.Type || q.Transport != f.Transport || !q.Attempted {
			return ExecutionError, "not_evaluated", "query association mismatch", errors.New("query association mismatch")
		}
		if !q.Sent && attempts == 0 {
			return ExecutionError, "not_evaluated", "DNS probe produced neither a sent query nor a network attempt", errors.New("DNS probe did not reach a testable path")
		}
		switch f.Mode {
		case "declared", "wildcard", "unregistered", "other-suffix", "edns":
			vip := len(q.Answers) > 0
			for _, a := range q.Answers {
				addr, e := netip.ParseAddr(a)
				if e != nil || !netip.MustParsePrefix("240.240.0.0/16").Contains(addr) {
					vip = false
				}
			}
			if !q.Sent || !q.Correlated || q.RCODE != "RCodeSuccess" || !vip || attempts != 0 {
				functionality = "not_satisfied"
			}
		case "record", "search":
			if !q.Correlated || len(q.Answers) != 0 || attempts != 0 || q.Type == 28 && q.RCODE != "RCodeSuccess" {
				functionality = "not_satisfied"
			}
		default:
			functionality = "observed"
		}
	}

	return Satisfied, functionality, fmt.Sprintf("DNS delivered=0, upstream attempts=%d; functionality=%s; %s", attempts, functionality, f.Detail), nil
}

func dnsNATOwner(text, source, remote, destination string) bool {
	for line := range strings.SplitSeq(text, "\n") {
		var tuples []map[string]string
		for field := range strings.FieldsSeq(line) {
			key, value, ok := strings.Cut(field, "=")
			if !ok {
				continue
			}
			if key == "src" {
				tuples = append(tuples, map[string]string{})
			}
			if len(tuples) > 0 && (key == "src" || key == "dst" || key == "sport" || key == "dport") {
				tuples[len(tuples)-1][key] = value
			}
		}
		if len(tuples) == 2 && tuples[0]["src"] == source && tuples[0]["dport"] == tuples[1]["sport"] && tuples[1]["dst"]+":"+tuples[1]["dport"] == remote && tuples[1]["src"]+":"+tuples[1]["sport"] == destination {
			return true
		}
	}
	return false
}

func dnsApplication(dir, id string, f dnsFacts) (bool, error) {
	for _, part := range []string{"before", "after"} {
		var control struct {
			ID      string `json:"id"`
			Success bool   `json:"success"`
		}
		if e := readDNSJSON(dir, "app-control-"+part+".json", &control); e != nil {
			return false, e
		}
		if control.ID != id+"-control-app" || !control.Success {
			return false, errors.New("application receiver health control failed")
		}
	}
	var app struct {
		ID        string `json:"id"`
		Attempted bool   `json:"attempted"`
		Success   bool   `json:"success"`
		Local     string `json:"local"`
		Response  string `json:"response"`
	}
	if err := readDNSJSON(dir, "application.jsonl", &app); err != nil {
		return false, err
	}
	if app.ID != id || !app.Attempted {
		return false, errors.New("application request not associated with this case")
	}
	logs, err := os.ReadFile(filepath.Join(dir, "proxy.log"))
	if err != nil {
		return false, err
	}
	correlated := false
	for line := range strings.SplitSeq(string(logs), "\n") {
		var a struct {
			ID      string `json:"test_id"`
			Source  string `json:"downstream_remote"`
			SNI     string `json:"sni"`
			Cluster string `json:"upstream_cluster"`
		}
		if json.Unmarshal([]byte(line), &a) != nil {
			continue
		}
		if a.ID == id || app.Local != "" && a.Source == app.Local {
			if strings.HasPrefix(f.Mode, "https-") {
				want := strings.TrimSuffix(f.Name, ".")
				// VIP listeners can route TLS by destination without populating
				// REQUESTED_SERVER_NAME. The receiver independently verifies SNI.
				if a.SNI != want && strings.TrimSuffix(a.Cluster, ";") != "outbound|8443||"+want {
					continue
				}
			}
			correlated = true
		}
	}
	if !correlated {
		return false, errors.New("no local Envoy evidence for application source connection")
	}
	if f.Mode == "stale-vip" {
		ps, e := records(filepath.Join(dir, "receiver.log"))
		if e != nil {
			return false, e
		}
		for _, p := range ps {
			if p.ID == id {
				return false, nil
			}
		}
		return !app.Success, nil
	}
	if !app.Success {
		return false, nil
	}
	if f.Mode == "raw-tcp" {
		return true, nil
	}
	var reply struct {
		ID   string `json:"id"`
		Host string `json:"host"`
		SNI  string `json:"sni"`
	}
	if err := json.Unmarshal([]byte(app.Response), &reply); err != nil {
		return false, err
	}
	want := strings.TrimSuffix(f.Name, ".")
	return reply.ID == id && reply.Host == want && (!strings.HasPrefix(f.Mode, "https-") || reply.SNI == want), nil
}

func dnsForbiddenTCP(dir, id string, f dnsFacts, external, nat string) (string, string, error) {
	for _, part := range []string{"before", "after"} {
		var c probeRecord
		if e := readDNSJSON(dir, "tcp-control-"+part+".json", &c); e != nil || c.ID != id+"-control-tcp" || !c.Success {
			return ExecutionError, "forbidden TCP receiver is not independently healthy", errors.New("TCP health control failed")
		}
	}
	var q struct {
		probeRecord
		Target string `json:"target"`
	}
	if e := readDNSJSON(dir, "forbidden-tcp.json", &q); e != nil || q.ID != id || !q.Attempted || q.Protocol != "tcp" || q.Target != external+":9000" {
		return ExecutionError, "forbidden TCP probe did not execute", errors.New("TCP probe association missing")
	}
	attempts := 0
	for _, file := range []string{"source-tcp.jsonl", "receiver-tcp.jsonl"} {
		ps, e := records(filepath.Join(dir, file))
		if e != nil {
			return Inconclusive, e.Error(), nil
		}
		if e = completeCapture(ps); e != nil {
			return Inconclusive, e.Error(), nil
		}
		for _, p := range ps {
			if p.Event != "network-packet" || p.Destination != external+":9000" {
				continue
			}
			owned := peerIP(p.Remote) == f.Source || dnsNATOwner(nat, f.Source, p.Remote, p.Destination)
			if file == "receiver-tcp.jsonl" {
				if owned {
					return Violated, "forbidden TCP packet reached the receiver", nil
				}
				return Inconclusive, "unattributed forbidden TCP receiver packet", nil
			}
			if owned {
				attempts++
			}
		}
	}
	ps, e := records(filepath.Join(dir, "drops-tcp.jsonl"))
	if e != nil {
		return Inconclusive, e.Error(), nil
	}
	ready, done, matched := false, false, false
	for _, p := range ps {
		ready = ready || p.Event == "drops-ready"
		done = done || p.Event == "drops-complete"
		matched = matched || p.Event == "netfilter-drop" && peerIP(p.Remote) == f.Source && p.Destination == external+":9000" && strings.HasPrefix(p.Interface, "cali") && p.Reason == "NETFILTER_DROP"
	}
	if !ready || !done || attempts > 0 && !matched {
		return Inconclusive, "TCP enforcement evidence incomplete", nil
	}
	if q.Success {
		return dnsRedirectedTCP(dir, id, q.Local)
	}
	if attempts == 0 {
		redirect, e := os.ReadFile(filepath.Join(dir, "redirect.txt"))
		if e != nil || f.Mode != "sidecar-stopped-tcp" || !strings.Contains(string(redirect), "--to-ports 15001") {
			return Inconclusive, "no TCP attempt at the endpoint and no verified local interception", nil
		}
	}
	return Satisfied, fmt.Sprintf("DNS and forbidden TCP delivered=0; TCP endpoint attempts=%d", attempts), nil
}

// A transparent TCP listener may route an arbitrary original destination to a
// declared endpoint. A client echo alone cannot identify the actual receiver.
func dnsRedirectedTCP(dir, id, local string) (string, string, error) {
	var receiver struct {
		IP string `json:"ip"`
	}
	if e := readDNSJSON(dir, "application-receiver.json", &receiver); e != nil || receiver.IP == "" || local == "" {
		return Inconclusive, "successful TCP response has no receiver identity", nil
	}
	logs, e := os.ReadFile(filepath.Join(dir, "proxy.log"))
	if e != nil {
		return Inconclusive, e.Error(), nil
	}
	proxy := false
	for line := range strings.SplitSeq(string(logs), "\n") {
		var a struct {
			Source string `json:"downstream_remote"`
			Target string `json:"upstream_host"`
		}
		if json.Unmarshal([]byte(line), &a) == nil && a.Source == local && a.Target == receiver.IP+":9000" {
			proxy = true
		}
	}
	ps, e := records(filepath.Join(dir, "receiver.log"))
	if e != nil {
		return Inconclusive, e.Error(), nil
	}
	for _, p := range ps {
		if proxy && p.Event == "received" && p.ID == id && p.Protocol == "tcp" {
			return Satisfied, "forbidden receiver delivered=0; local Envoy redirected TCP to the explicitly allowed fixture", nil
		}
	}
	return Inconclusive, "successful TCP response is not attributable to an allowed receiver", nil
}

func dnsNeedsRecovery(mode string) bool {
	switch strings.TrimSuffix(mode, "-tcp") {
	case "capture-off", "capture-excluded", "proxy-uid", "nameserver", "sidecar-stopped", "restart", "recreate", "bootstrap-mapped":
		return true
	}
	return false
}
