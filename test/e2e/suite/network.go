package suite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type enforcementEvidence struct {
	ID        string `json:"id"`
	SourceIP  string `json:"source_ip"`
	Interface string `json:"interface"`
	Before    string `json:"before"`
	After     string `json:"after"`
	Address   string `json:"address"`
}

var counterLine = regexp.MustCompile(`^\[([0-9]+):[0-9]+\] (.+)$`)

func checkEnforcement(dir, id, source string) error {
	data, err := os.ReadFile(filepath.Join(dir, "enforcement.json"))
	if err != nil {
		return err
	}
	var e enforcementEvidence
	if err = json.Unmarshal(data, &e); err != nil {
		return err
	}
	if e.ID != id || e.SourceIP != source || source == "" || !strings.HasPrefix(e.Interface, "cali") {
		return errors.New("enforcement observation does not identify this case's source endpoint")
	}
	if e.Address != "" {
		drops, err := records(filepath.Join(dir, "drops.jsonl"))
		if err != nil {
			return err
		}
		ready, complete, matched := false, false, false
		for _, p := range drops {
			ready = ready || p.Event == "drops-ready"
			complete = complete || p.Event == "drops-complete"
			matched = matched || p.Event == "netfilter-drop" && p.Reason == "NETFILTER_DROP" && peerIP(p.Remote) == source && p.Destination == e.Address && p.Interface == e.Interface
		}
		if ready && complete && matched {
			return nil
		}
		return errors.New("no complete kernel drop observation associated with this source interface and destination")
	}
	counts := func(text string) map[string]uint64 {
		m := map[string]uint64{}
		for line := range strings.SplitSeq(text, "\n") {
			match := counterLine.FindStringSubmatch(line)
			if len(match) != 3 || !strings.HasPrefix(match[2], "-A cali-fw-"+e.Interface+" ") || !strings.HasSuffix(match[2], "-j DROP") {
				continue
			}
			n, _ := strconv.ParseUint(match[1], 10, 64)
			m[match[2]] = n
		}
		return m
	}
	before, after := counts(e.Before), counts(e.After)
	for rule, n := range after {
		if old, ok := before[rule]; ok && n > old {
			return nil
		}
	}
	return errors.New("no attributable Calico DROP counter increase (rule replacement is not counter evidence)")
}

func completeCapture(packets []probeRecord) error {
	ready, complete := false, false
	for _, p := range packets {
		if p.Event == "capture-ready" {
			ready = true
		}
		if p.Event == "capture-complete" {
			complete = p.Dropped != nil && *p.Dropped == 0 && p.KernelPackets != nil && p.Captured != nil && *p.KernelPackets == *p.Captured
		}
	}
	if !ready || !complete {
		return errors.New("capture did not complete without dropped or unread packets")
	}
	return nil
}

type networkFacts struct {
	ID             string    `json:"id"`
	Protocol       string    `json:"protocol"`
	Target         string    `json:"target"`
	Phase          string    `json:"phase"`
	SourceIP       string    `json:"source_ip"`
	ReceiverBefore string    `json:"receiver_before"`
	ReceiverAfter  string    `json:"receiver_after"`
	Restored       bool      `json:"restored"`
	FaultVerified  bool      `json:"fault_verified"`
	FaultStart     time.Time `json:"fault_start"`
	FaultEnd       time.Time `json:"fault_end"`
	PolicyWait     int       `json:"policy_wait_seconds"`
	PolicyUpdated  time.Time `json:"policy_updated"`
}

func evaluateNetwork(dir, id, contract string, expected egressInputs) (string, string, error) {
	if contract == "chain" {
		if expected != (egressInputs{Protocol: "http", Target: "mesh-routed", Phase: "primary-restart"}) {
			return ExecutionError, "unexpected chaining case inputs", nil
		}
		return evaluateEgress(dir, id, "gateway", egressInputs{Protocol: "http", Target: "routed", Client: "workload", Phase: "fresh"})
	}
	data, err := os.ReadFile(filepath.Join(dir, "network.json"))
	if err != nil {
		return "", "", err
	}
	var f networkFacts
	if err = json.Unmarshal(data, &f); err != nil {
		return "", "", err
	}
	if f.ID != id || f.Protocol != expected.Protocol || f.Target != expected.Target || f.Phase != expected.Phase || !f.Restored || !f.FaultVerified || f.ReceiverBefore == "" || f.ReceiverBefore != f.ReceiverAfter {
		return ExecutionError, "case identity, receiver stability, fault or restoration evidence invalid", nil
	}
	for _, part := range []string{"before", "after"} {
		ps, err := records(filepath.Join(dir, "control-"+part+".jsonl"))
		if err != nil {
			return "", "", err
		}
		valid := false
		for _, p := range ps {
			valid = valid || p.ID == id+"-control-"+part && p.Attempted && p.Success
		}
		if !valid {
			return ExecutionError, "receiver control failed " + part, nil
		}
	}
	probe, err := records(filepath.Join(dir, "probe.jsonl"))
	if err != nil {
		return "", "", err
	}
	attempts, successes := 0, 0
	for _, p := range probe {
		if p.ID == id && p.Attempted {
			attempts++
			if p.Success {
				successes++
			}
		}
	}
	if attempts == 0 && contract != "startup" {
		return Inconclusive, "no attributable application attempt", nil
	}
	if expected.Phase == "proxy-uid" {
		for _, p := range probe {
			if p.ID == id && p.Attempted && p.UID != 1337 {
				return ExecutionError, "the bypass probe did not run with the excluded proxy UID", nil
			}
		}
	}
	if expected.Phase != "healthy" && expected.Phase != "capture" {
		allow, err := records(filepath.Join(dir, "recovery-allow.jsonl"))
		if err != nil {
			return "", "", err
		}
		if len(allow) < 2 || !allow[len(allow)-1].Success || !allow[len(allow)-2].Success {
			return ExecutionError, "allowed path did not recover", nil
		}
		result, reason, err := evaluateNetwork(filepath.Join(dir, "recovery-deny"), id+"-recovery-deny", "deny", egressInputs{Protocol: "tcp", Target: "np-wrong", Phase: "healthy"})
		if err != nil || result != Satisfied {
			return ExecutionError, "isolation recovery failed: " + reason, err
		}
	}
	if contract == "recovery" {
		contract = "allow"
	}
	if contract == "observe" {
		if f.PolicyUpdated.IsZero() {
			return ExecutionError, "missing realized policy update time", nil
		}
		connection := ""
		before, after := 0, 0
		persisted := false
		for _, p := range probe {
			if p.ID != id || !p.Attempted {
				continue
			}
			if p.Started.Before(f.PolicyUpdated) && p.Success {
				if connection != "" && connection != p.Local {
					return Inconclusive, "existing stream reconnected before the policy update", nil
				}
				connection = p.Local
				before++
			} else if p.Started.After(f.PolicyUpdated) {
				after++
				if p.Success {
					if connection == "" || connection != p.Local {
						return Inconclusive, "existing stream silently reconnected after policy update", nil
					}
					persisted = true
				}
			}
		}
		if before == 0 || after == 0 {
			return Inconclusive, "missing observations on both sides of the policy update", nil
		}
		return Satisfied, fmt.Sprintf("existing TCP persisted=%t; new-connection isolation revalidated independently; immediate established-flow revocation is not claimed", persisted), nil
	}
	if contract == "startup" {
		if attempts == 0 {
			return evaluateBlockedStartup(dir, id, f)
		}
		if f.PolicyWait <= 0 || f.FaultStart.IsZero() || f.FaultEnd.Sub(f.FaultStart) < time.Duration(f.PolicyWait+5)*time.Second {
			return ExecutionError, "startup fault did not extend past the actual CNI policy wait", nil
		}
		var state struct {
			UID     string    `json:"uid"`
			Created time.Time `json:"created"`
			IP      string    `json:"ip"`
		}
		data, err := os.ReadFile(filepath.Join(dir, "startup.json"))
		if err != nil {
			return "", "", err
		}
		if err = json.Unmarshal(data, &state); err != nil {
			return "", "", err
		}
		if state.UID == "" || state.IP != f.SourceIP || state.Created.Before(f.FaultStart) {
			return ExecutionError, "startup Pod was not created under the verified fault", nil
		}
		postTimeout := false
		for _, p := range probe {
			if p.ID != id || !p.Attempted {
				continue
			}
			if p.Started.Before(state.Created) || p.Finished.After(f.FaultEnd.Add(time.Second)) {
				return ExecutionError, "first-packet probe is outside the verified fault", nil
			}
			postTimeout = postTimeout || p.Started.After(state.Created.Add(time.Duration(f.PolicyWait)*time.Second))
		}
		if !postTimeout {
			return Inconclusive, "no application probe after the CNI policy wait expired", nil
		}
		contract = "deny"
	}
	if contract == "allow" {
		if successes != attempts {
			return Violated, "whitelisted destination failed despite healthy receiver", nil
		}
		return Satisfied, "correlated response from the whitelisted tuple", nil
	}
	if contract == "gateway" {
		if successes != attempts {
			return Violated, "gateway endpoint did not return all correlated responses", nil
		}
		if err := gatewayHostEvidence(dir, id, expected.Protocol, "gateway-endpoint.test", probe); err != nil {
			return Inconclusive, err.Error(), nil
		}
		return Satisfied, "endpoint address retained both proxy hops and expected mTLS identities", nil
	}
	if contract == "capture" {
		data, err := os.ReadFile(filepath.Join(dir, "workload.log"))
		if err != nil {
			return "", "", err
		}
		for line := range strings.SplitSeq(string(data), "\n") {
			var hop struct {
				Remote  string `json:"downstream_remote"`
				Local   string `json:"downstream_local"`
				Cluster string `json:"upstream_cluster"`
			}
			if json.Unmarshal([]byte(line), &hop) != nil {
				continue
			}
			for _, p := range probe {
				if p.ID == id && p.Attempted && p.Connected && p.Local != "" && hop.Remote == p.Local && hop.Local == p.Remote && hop.Cluster != "" && hop.Cluster != "-" {
					return Satisfied, "the local workload Envoy accepted the application's raw TCP connection with the original destination", nil
				}
			}
		}
		return Inconclusive, "local Envoy has not recorded the raw TCP source connection", nil
	}
	if contract == "deny" {
		if successes > 0 {
			return Violated, "forbidden application response", nil
		}
		packets, err := records(filepath.Join(dir, "packets.jsonl"))
		if err != nil {
			return "", "", err
		}
		// Node AF_PACKET is upstream of INPUT. Its packet observations are not
		// post-firewall delivery; the listening socket is the receiver there.
		node := strings.HasSuffix(f.Target, "node")
		if node {
			rs, err := records(filepath.Join(dir, "receiver.log"))
			if err != nil {
				return "", "", err
			}
			for _, r := range rs {
				if (r.Event == "connection" || r.Event == "received") && peerIP(r.Remote) == f.SourceIP {
					return Violated, "node listener accepted the forbidden source", nil
				}
			}
		} else {
			controls := map[string]bool{}
			for _, part := range []string{"before", "after"} {
				ps, err := records(filepath.Join(dir, "control-"+part+".jsonl"))
				if err != nil {
					return "", "", err
				}
				seen := false
				for _, p := range ps {
					if p.ID != id+"-control-"+part || !p.Success || p.Local == "" {
						continue
					}
					controls[p.Local] = true
					for _, r := range packets {
						seen = seen || r.Event == "network-packet" && r.Remote == p.Local
					}
				}
				if !seen {
					return Inconclusive, "receiver capture missed positive control " + part, nil
				}
			}
			for _, r := range packets {
				if r.Event == "network-packet" && !controls[r.Remote] {
					if peerIP(r.Remote) == f.SourceIP {
						return Violated, "receiver observed packets from the forbidden source", nil
					}
					return Inconclusive, "receiver traffic lacks a source or NAT association", nil
				}
			}
		}
		if err := completeCapture(packets); err != nil {
			return Inconclusive, err.Error(), nil
		}
		sender, err := records(filepath.Join(dir, "sender.jsonl"))
		if err != nil {
			return "", "", err
		}
		sent := false
		for _, p := range sender {
			sent = sent || p.Event == "network-packet" && peerIP(p.Remote) == f.SourceIP
		}
		if !sent {
			return Inconclusive, "no source packet reached the enforcing interface", nil
		}
		if err := completeCapture(sender); err != nil {
			return Inconclusive, err.Error(), nil
		}
		if err := checkEnforcement(dir, id, f.SourceIP); err != nil {
			return Inconclusive, err.Error(), nil
		}
		return Satisfied, "source emitted packets; Calico dropped them; healthy receiver had no delivery", nil
	}
	return ExecutionError, fmt.Sprintf("network contract %q has no evidence evaluator", contract), nil
}

// A Pending Pod is only safe evidence when the CNI explicitly refused sandbox
// creation for policy setup, not when scheduling or image startup failed.
func evaluateBlockedStartup(dir, id string, f networkFacts) (string, string, error) {
	if f.PolicyWait <= 0 || f.FaultStart.IsZero() || f.FaultEnd.Sub(f.FaultStart) < time.Duration(f.PolicyWait+5)*time.Second {
		return ExecutionError, "blocked startup did not span the CNI policy wait", nil
	}
	var pod struct {
		UID, IP, Node string
		Created       time.Time
		Conditions    []struct{ Type, Status string }
		Containers    []struct {
			ContainerID      string
			RestartCount     int
			State, LastState map[string]json.RawMessage
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "startup.json"))
	if err != nil {
		return ExecutionError, "startup Pod evidence missing", err
	}
	if err = json.Unmarshal(data, &pod); err != nil {
		return ExecutionError, "invalid startup Pod evidence", err
	}
	if pod.UID == "" || pod.Node == "" || pod.Created.Before(f.FaultStart) || f.FaultEnd.Sub(pod.Created) < time.Duration(f.PolicyWait+5)*time.Second {
		return ExecutionError, "startup identity, placement or observation window invalid", nil
	}
	scheduled, sandboxBlocked := false, false
	for _, c := range pod.Conditions {
		scheduled = scheduled || c.Type == "PodScheduled" && c.Status == "True"
		sandboxBlocked = sandboxBlocked || c.Type == "PodReadyToStartContainers" && c.Status == "False"
	}
	if !scheduled || !sandboxBlocked {
		return ExecutionError, "no proven sandbox startup block", nil
	}
	for _, c := range pod.Containers {
		if c.ContainerID != "" || c.RestartCount != 0 || len(c.LastState) != 0 || c.State["running"] != nil || c.State["terminated"] != nil {
			return Inconclusive, "a startup container may have executed without probe evidence", nil
		}
	}
	var events []struct {
		UID, Reason, Message string
		Time                 time.Time
	}
	data, err = os.ReadFile(filepath.Join(dir, "startup-events.json"))
	if err != nil {
		return ExecutionError, "CNI refusal evidence missing", err
	}
	if err = json.Unmarshal(data, &events); err != nil {
		return ExecutionError, "invalid CNI refusal evidence", err
	}
	refused := false
	for _, e := range events {
		message := strings.ToLower(e.Message)
		refused = refused || e.UID == pod.UID && e.Reason == "FailedCreatePodSandBox" &&
			!e.Time.Before(pod.Created.Add(time.Duration(f.PolicyWait)*time.Second)) && !e.Time.After(f.FaultEnd) &&
			strings.Contains(message, "calico") && strings.Contains(message, "policy") &&
			(strings.Contains(message, "timed out") || strings.Contains(message, "timeout")) &&
			strings.Contains(message, "failed")
	}
	if !refused {
		return ExecutionError, "Pending is not attributable to a Calico policy refusal after the wait deadline", nil
	}
	packets, err := records(filepath.Join(dir, "packets.jsonl"))
	if err != nil {
		return Inconclusive, "receiver observation missing", err
	}
	if err := completeCapture(packets); err != nil {
		return Inconclusive, err.Error(), nil
	}
	receiver, err := records(filepath.Join(dir, "receiver.log"))
	if err != nil {
		return Inconclusive, "receiver log missing", err
	}
	controls := map[string]bool{}
	for _, part := range []string{"before", "after"} {
		seen := false
		for _, r := range receiver {
			if r.ID == id+"-control-"+part && r.Remote != "" {
				controls[r.Remote] = true
				for _, p := range packets {
					seen = seen || p.Event == "network-packet" && p.Remote == r.Remote
				}
			}
		}
		if !seen {
			return Inconclusive, "blocked-startup observer missed receiver control", nil
		}
	}
	for _, r := range receiver {
		if r.ID == id {
			return Violated, "blocked startup nevertheless reached receiver", nil
		}
	}
	for _, p := range packets {
		if p.Event == "network-packet" && !controls[p.Remote] {
			return Inconclusive, "unattributed traffic during blocked startup", nil
		}
	}
	return Satisfied, "Calico policy refusal kept the sandbox and application stopped beyond the wait deadline; recovery verified", nil
}
