package suite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	core "k8s.io/api/core/v1"
)

func checkIntegrationChains(dir string) error {
	var base map[string]any
	if err := readEvidence(dir, "cni-before.json", &base); err != nil {
		return err
	}
	plugins, ok := base["plugins"].([]any)
	if !ok || len(plugins) != 3 {
		return errors.New("missing standalone CNI baseline")
	}
	for _, stage := range []string{"initial", "restarted", "final", "restored"} {
		var current map[string]any
		if err := readEvidence(dir, "cni-"+stage+".json", &current); err != nil {
			return err
		}
		if stage != "restored" {
			chain, ok := current["plugins"].([]any)
			if !ok || len(chain) != 4 {
				return fmt.Errorf("%s: missing fixed four-plugin chain", stage)
			}
			last, ok := chain[3].(map[string]any)
			if !ok || last["type"] != "istio-cni" || last["ambient_enabled"] != false || last["native_nftables"] != false {
				return fmt.Errorf("%s: unsupported Istio CNI configuration", stage)
			}
			current["plugins"] = chain[:3]
		}
		if !reflect.DeepEqual(base, current) {
			return fmt.Errorf("%s: CNI composition changed the foundation configuration", stage)
		}
	}
	var originalUID string
	for _, stage := range []string{"initial", "restarted", "final"} {
		var agents []struct {
			UID, RequestedImage string
			Containers          []struct {
				Image, ImageID string
				Ready          bool
			}
		}
		if err := readEvidence(dir, "cni-agent-"+stage+".json", &agents); err != nil {
			return err
		}
		if len(agents) != 1 || agents[0].UID == "" || len(agents[0].Containers) != 1 {
			return errors.New("ambiguous CNI agent identity")
		}
		c := agents[0].Containers[0]
		if !c.Ready || c.ImageID == "" || agents[0].RequestedImage != "docker.io/istio/install-cni:1.31.0@sha256:8cef43ba08ae1af846d0e474591f625cd2dd6b2c0df0efcb17faef0d978ef246" {
			return errors.New("CNI agent image or readiness evidence invalid")
		}
		if stage == "initial" {
			originalUID = agents[0].UID
		} else if agents[0].UID == originalUID {
			return errors.New("CNI agent restart was not observed")
		}
	}
	return nil
}

func checkNetworkPreparation(dir, id string) error {
	var prep namespaceState
	if err := readEvidence(filepath.Join(dir, "preparation"), "network-state.json", &prep); err != nil {
		return err
	}
	if prep.ID != id || prep.Event != "network-state" || prep.UID != 0 || prep.GID != 0 || prep.Started.IsZero() || prep.Finished.Before(prep.Started) || prep.Identity["NoNewPrivs"] != "1" || prep.Identity["Seccomp"] != "2" {
		return errors.New("trusted preparation execution or privilege evidence invalid")
	}
	for _, key := range []string{"CapEff", "CapPrm", "CapBnd"} {
		value, err := strconv.ParseUint(prep.Identity[key], 16, 64)
		if err != nil || value != 0x3000 {
			return fmt.Errorf("preparation %s is not exactly NET_ADMIN and NET_RAW", key)
		}
	}
	if err := validateIPv6State(prep); err != nil {
		return err
	}
	var pod struct {
		UID        string
		Containers []struct {
			Name  string
			State core.ContainerState
		}
	}
	if err := readEvidence(dir, "pod.json", &pod); err != nil {
		return err
	}
	states := map[string]core.ContainerState{}
	for _, c := range pod.Containers {
		states[c.Name] = c.State
	}
	prepared, first := states["prepare-network"].Terminated, states["first-probe"].Terminated
	if pod.UID == "" || prepared == nil || first == nil || prepared.ExitCode != 0 || first.ExitCode != 0 || prepared.FinishedAt.IsZero() || first.StartedAt.Before(&prepared.FinishedAt) {
		return errors.New("network preparation did not terminate before business init")
	}
	for _, name := range []string{"probe", "istio-proxy"} {
		state := states[name].Running
		if state == nil || state.StartedAt.Before(&first.FinishedAt) {
			return fmt.Errorf("%s started before terminating preparation and business init", name)
		}
	}
	for name, required := range map[string][]string{
		"capture-rules.txt":    {"-A OUTPUT -j ISTIO_OUTPUT", "--uid-owner 10000 -j RETURN"},
		"preparation-ipv4.txt": {"-A OUTPUT -d 127.0.0.1/32 -j NETWORKING_PREP", "-A NETWORKING_PREP -p tcp -m tcp --dport 19091 -j REJECT"},
		"preparation-ipv6.txt": {"-A OUTPUT -d ::1/128 -j NETWORKING_PREP", "-A NETWORKING_PREP -p tcp -m tcp --dport 19091 -j REJECT"},
	} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		for _, text := range required {
			if !strings.Contains(string(data), text) {
				return fmt.Errorf("%s: expected executed CNI/preparation rule missing: %s", name, text)
			}
		}
	}
	return nil
}

func evaluateIntegration(dir, id string) (string, string, error) {
	var receipt struct {
		ID       string
		Restored bool
	}
	if err := readEvidence(dir, "integration.json", &receipt); err != nil {
		return ExecutionError, "integration did not complete restoration", err
	}
	if receipt.ID != id || !receipt.Restored {
		return ExecutionError, "integration identity or restoration invalid", nil
	}
	if err := checkIntegrationChains(dir); err != nil {
		return ExecutionError, err.Error(), nil
	}
	for _, stage := range []string{"initial", "blocked", "recovered"} {
		path, correlation := filepath.Join(dir, stage), id+"-"+stage
		phase, contract := "first-init", "first-packet"
		if stage == "blocked" {
			phase, contract = "felix-init", "startup"
		}
		result, reason, err := evaluateNetwork(path, correlation, contract, egressInputs{Protocol: "tcp", Target: "np-external", Phase: phase})
		if err != nil || result != Satisfied {
			return result, stage + ": " + reason, err
		}
		if stage == "blocked" {
			continue
		}
		integration := filepath.Join(path, "integration")
		if err := checkNetworkPreparation(integration, correlation); err != nil {
			return ExecutionError, stage + ": " + err.Error(), nil
		}
		result, reason, err = evaluateIPv6Execution(integration, correlation)
		if err != nil || result != Satisfied {
			return result, stage + ": " + reason, err
		}
		probes, err := records(filepath.Join(path, "probe.jsonl"))
		if err != nil {
			return ExecutionError, "missing preparation/first-init attempts", err
		}
		drops, err := records(filepath.Join(path, "drops.jsonl"))
		if err != nil {
			return ExecutionError, "missing preparation/first-init drops", err
		}
		var enforcement enforcementEvidence
		if err := readEvidence(path, "enforcement.json", &enforcement); err != nil {
			return ExecutionError, "missing enforcement identity", err
		}
		if err := checkPreparationDrops(probes, drops, enforcement, correlation); err != nil {
			return Inconclusive, stage + ": " + err.Error(), nil
		}

	}
	return Satisfied, "fixed upstream CNI chain preserves startup policy, IPv6 closure and external confinement through trusted preparation, component restart and policy-fault recovery", nil
}

func checkPreparationDrops(probes, drops []probeRecord, e enforcementEvidence, id string) error {
	seen := map[int]bool{}
	for _, p := range probes {
		if p.ID != id || p.Protocol != "tcp" || !p.Attempted || p.Target != e.Address || p.Started.IsZero() || p.Finished.Before(p.Started) {
			continue
		}
		for _, d := range drops {
			if d.Event == "netfilter-drop" && d.Reason == "NETFILTER_DROP" && peerIP(d.Remote) == e.SourceIP && d.Destination == p.Target && d.Interface == e.Interface && !d.Time.Before(p.Started) && !d.Time.After(p.Finished) {
				seen[p.UID] = true
			}
		}
	}
	if !seen[0] || !seen[10000] {
		return errors.New("both privileged preparation and restricted business require an attributable forbidden TCP drop during their own attempt")
	}
	return nil
}
