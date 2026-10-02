package suite

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func readEvidence(dir, name string, value any) error {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func validateIPv6State(state namespaceState) error {
	for _, name := range []string{"all", "default", "lo", "eth0"} {
		if state.DisableIPv6[name] != "1" {
			return fmt.Errorf("IPv6 remains enabled or unverified on %s", name)
		}
	}
	for name, addresses := range state.Addresses {
		if state.DisableIPv6[name] != "1" && state.DisableIPv6[name] != "unavailable" {
			return fmt.Errorf("IPv6 interface %s is not disabled", name)
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address)
			if err != nil || !prefix.Addr().Is4() {
				return fmt.Errorf("unexpected address %q on %s", address, name)
			}
		}
	}
	if _, ok := state.Addresses["lo"]; !ok {
		return errors.New("missing loopback observation")
	}
	if _, ok := state.Addresses["eth0"]; !ok {
		return errors.New("missing workload interface observation")
	}
	if value, ok := state.Files["/proc/net/if_inet6"]; !ok || strings.TrimSpace(value) != "" {
		return errors.New("IPv6 address table not proven empty")
	}
	routes, ok := state.Files["/proc/net/ipv6_route"]
	if !ok {
		return errors.New("missing IPv6 route table")
	}
	for line := range strings.SplitSeq(routes, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 10 {
			return errors.New("invalid IPv6 route observation")
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err != nil || flags&0x200 == 0 {
			return errors.New("usable IPv6 route remains")
		}
	}
	return nil
}

func evaluateIPv6Execution(dir, id string) (string, string, error) {
	var pod struct {
		UID     string
		Created time.Time
		IP      string
	}
	if err := readEvidence(dir, "pod.json", &pod); err != nil {
		return "", "", err
	}
	if pod.UID == "" || pod.Created.IsZero() || pod.IP == "" {
		return ExecutionError, "missing IPv6 workload identity", nil
	}
	for _, stage := range []string{"first-init", "app"} {
		path := filepath.Join(dir, stage)
		state, err := readNamespaceState(path, id)
		if err != nil {
			return ExecutionError, err.Error(), nil
		}
		if state.Started.Before(pod.Created) {
			return ExecutionError, "namespace observation predates this Pod", nil
		}
		if err := validateIPv6State(state); err != nil {
			return Violated, stage + ": " + err.Error(), nil
		}
		probes, err := records(filepath.Join(path, "probe.jsonl"))
		if err != nil {
			return "", "", err
		}
		seen := map[string]bool{}
		for _, p := range probes {
			key := p.Protocol + " " + p.Target
			expected := slices.Contains([]string{"tcp6 [::1]:19091", "tcp6 [fe80::ecee:eeff:feee:eeee%eth0]:19091", "udp6 [::1]:19091", "udp6 [fe80::ecee:eeff:feee:eeee%eth0]:19091", "listen-tcp6 [::1]:0"}, key)
			if !expected || seen[key] || p.ID != id || p.UID != 10000 || !p.Attempted || p.Event != "ipv6-attempt" || p.Started.Before(state.Finished) || p.Finished.Before(p.Started) {
				return ExecutionError, "invalid IPv6 attempt association", nil
			}
			if p.Success {
				return Violated, stage + ": IPv6 communication or listener remains available", nil
			}
			if !slices.Contains([]int{97, 99, 101}, p.SocketError) {
				return Inconclusive, "IPv6 failure is not disabled-family/address/route evidence", nil
			}
			seen[key] = true
		}
		if len(seen) != 5 {
			return Inconclusive, "missing IPv6 operation or target attempt", nil
		}
	}
	controls, err := records(filepath.Join(dir, "ipv4.jsonl"))
	if err != nil {
		return "", "", err
	}
	if len(controls) != 1 || controls[0].ID != id+"-ipv4" || controls[0].UID != 10000 || !controls[0].Attempted || !controls[0].Success {
		return ExecutionError, "IPv4 allowed path did not remain functional", nil
	}
	return Satisfied, "IPv6 disabled before business init and app, including loopback and link-local; IPv4 control works with unchanged privileges", nil
}

func evaluateIPv6(dir, id, contract string, expected egressInputs) (string, string, error) {
	var facts struct {
		ID, Phase string
		Restored  bool
	}
	if err := readEvidence(dir, "ipv6.json", &facts); err != nil {
		return "", "", err
	}
	if facts.ID != id || facts.Phase != expected.Phase || expected.Protocol != "ipv6" || contract != "ipv6-closure" || !facts.Restored {
		return ExecutionError, "invalid IPv6 case identity or recovery", nil
	}
	if expected.Phase == "first-execution" {
		return evaluateIPv6Execution(dir, id)
	}
	if expected.Phase != "cni-failure" {
		return ExecutionError, "unknown IPv6 phase", nil
	}
	var pod struct {
		UID        string
		Created    time.Time
		Containers []struct {
			ContainerID      string
			RestartCount     int
			State, LastState map[string]json.RawMessage
		}
		Conditions []struct{ Type, Status string }
	}
	if err := readEvidence(dir, "blocked-pod.json", &pod); err != nil {
		return "", "", err
	}
	if pod.UID == "" || pod.Created.IsZero() {
		return ExecutionError, "missing attempted startup identity", nil
	}
	scheduled, sandboxBlocked := false, false
	for _, condition := range pod.Conditions {
		scheduled = scheduled || condition.Type == "PodScheduled" && condition.Status == "True"
		sandboxBlocked = sandboxBlocked || condition.Type == "PodReadyToStartContainers" && condition.Status == "False"
	}
	if !scheduled || !sandboxBlocked {
		return Inconclusive, "missing scheduled Pod and blocked sandbox state", nil
	}
	for _, c := range pod.Containers {
		if c.ContainerID != "" || c.RestartCount != 0 || c.State["running"] != nil || c.State["terminated"] != nil || len(c.LastState) > 0 {
			return Violated, "business init or app started despite failed CNI setup", nil
		}
	}
	var events struct {
		Items []struct {
			Reason, Message string
			InvolvedObject  struct{ UID string }
		}
	}
	if err := readEvidence(dir, "blocked-events.json", &events); err != nil {
		return "", "", err
	}
	matched := false
	for _, e := range events.Items {
		matched = matched || e.InvolvedObject.UID == pod.UID && e.Reason == "FailedCreatePodSandBox" && strings.Contains(e.Message, "tuning") && strings.Contains(e.Message, "missing-"+id)
	}
	if !matched {
		return Inconclusive, "startup was not attributed to the injected CNI failure", nil
	}
	before, err := os.ReadFile(filepath.Join(dir, "cni-before.json"))
	if err != nil {
		return "", "", err
	}
	after, err := os.ReadFile(filepath.Join(dir, "cni-restored.json"))
	if err != nil {
		return "", "", err
	}
	if !bytes.Equal(before, after) {
		return ExecutionError, "CNI configuration was not restored", nil
	}
	result, reason, err := evaluateIPv6Execution(filepath.Join(dir, "recovery"), id)
	if result != Satisfied || err != nil {
		return result, "CNI recovery: " + reason, err
	}
	return Satisfied, "CNI IPv6 setup failure prevented sandbox and business startup; exact configuration restored and new init/app IPv6 closure plus IPv4 revalidated", nil
}
