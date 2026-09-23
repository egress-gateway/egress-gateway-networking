package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEnforcementEvidenceNeedsTheCaseEndpointAndActualDrop(t *testing.T) {
	for _, change := range []string{"none", "id", "source", "interface", "zero", "reset", "not-drop", "other-endpoint"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			e := enforcementEvidence{ID: "attempt", SourceIP: "10.1.0.2", Interface: "cali123", Before: "[2:100] -A cali-fw-cali123 -j DROP\n", After: "[3:160] -A cali-fw-cali123 -j DROP\n"}
			switch change {
			case "id":
				e.ID = "other"
			case "source":
				e.SourceIP = "10.1.0.3"
			case "interface":
				e.Interface = ""
			case "other-endpoint":
				e.Interface = "cali456"
			case "zero":
				e.After = e.Before
			case "reset":
				e.After = "[0:0] -A cali-fw-test -j DROP\n"
			case "not-drop":
				e.Before = "[2:100] -A cali-fw-test -j RETURN\n"
				e.After = "[3:160] -A cali-fw-test -j RETURN\n"
			}
			data, _ := json.Marshal(e)
			if err := os.WriteFile(filepath.Join(dir, "enforcement.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			err := checkEnforcement(dir, "attempt", "10.1.0.2")
			if (err == nil) != (change == "none") {
				t.Fatalf("%s: %v", change, err)
			}
		})
	}
}

func TestCaptureWindowRequiresLosslessCompletionAndObservedControl(t *testing.T) {
	packets := []probeRecord{{Event: "capture-ready"}, {Event: "network-packet", Remote: "10.1.0.9:40000"}, {Event: "capture-complete", Dropped: new(uint32(0)), KernelPackets: new(uint32(1)), Captured: new(uint32(1))}}
	if err := completeCapture(packets); err != nil {
		t.Fatal(err)
	}
	packets[2].Dropped = new(uint32(1))
	if err := completeCapture(packets); err == nil {
		t.Fatal("packet loss accepted")
	}
	if err := completeCapture(packets[:2]); err == nil {
		t.Fatal("unfinished capture accepted")
	}
}

func TestNetworkDenialRequiresIndependentCompleteEvidence(t *testing.T) {
	for _, scenario := range []struct{ name, want string }{
		{"complete", Satisfied}, {"not-attempted", Inconclusive}, {"wrong-id", Inconclusive},
		{"fault-not-effective", ExecutionError}, {"recovery-failed", ExecutionError},
		{"receiver-unhealthy", ExecutionError}, {"receiver-changed", ExecutionError},
		{"capture-loss", Inconclusive}, {"no-drop", Inconclusive}, {"no-emission", Inconclusive},
		{"unattributed", Inconclusive}, {"delivered", Violated}, {"additive-allow", Violated},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name string, value any) {
				t.Helper()
				b, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stream := func(name string, ps []probeRecord) {
				t.Helper()
				var b []byte
				for _, p := range ps {
					line, err := json.Marshal(p)
					if err != nil {
						t.Fatal(err)
					}
					b = append(b, append(line, '\n')...)
				}
				if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			facts := networkFacts{ID: "request", Protocol: "tcp", Target: "np-wrong", Phase: "healthy", SourceIP: "10.0.0.2", ReceiverBefore: "pod-uid", ReceiverAfter: "pod-uid", Restored: true, FaultVerified: true}
			switch scenario.name {
			case "fault-not-effective":
				facts.FaultVerified = false
			case "recovery-failed":
				facts.Restored = false
			case "receiver-changed":
				facts.ReceiverAfter = "other-uid"
			}
			write("network.json", facts)
			for _, part := range []string{"before", "after"} {
				write("control-"+part+".jsonl", probeRecord{ID: "request-control-" + part, Attempted: true, Success: scenario.name != "receiver-unhealthy", Local: "10.0.0.3:40000"})
			}
			p := probeRecord{ID: "request", Attempted: true}
			switch scenario.name {
			case "not-attempted":
				p.Attempted = false
			case "wrong-id":
				p.ID = "wrong"
			case "additive-allow":
				p.Success = true
			}
			write("probe.jsonl", p)
			packets := []probeRecord{{Event: "capture-ready"}, {Event: "network-packet", Remote: "10.0.0.3:40000"}, {Event: "capture-complete", Dropped: new(uint32(0)), KernelPackets: new(uint32(1)), Captured: new(uint32(1))}}
			switch scenario.name {
			case "capture-loss":
				packets[2].Dropped = new(uint32(1))
			case "unattributed":
				packets = append(packets, probeRecord{Event: "network-packet", Remote: "10.0.0.9:41000"})
			case "delivered":
				packets = append(packets, probeRecord{Event: "network-packet", Remote: "10.0.0.2:41000"})
			}
			stream("packets.jsonl", packets)
			emission := []probeRecord{{Event: "capture-ready"}, {Event: "network-packet", Remote: "10.0.0.2:41000"}, {Event: "capture-complete", Dropped: new(uint32(0)), KernelPackets: new(uint32(1)), Captured: new(uint32(1))}}
			if scenario.name == "no-emission" {
				emission[1].Remote = "10.0.0.9:41000"
			}
			stream("sender.jsonl", emission)
			e := enforcementEvidence{ID: "request", SourceIP: "10.0.0.2", Interface: "cali123", Before: "[0:0] -A cali-fw-cali123 -j DROP\n", After: "[1:60] -A cali-fw-cali123 -j DROP\n"}
			if scenario.name == "no-drop" {
				e.After = e.Before
			}
			write("enforcement.json", e)
			actual, reason, err := evaluateNetwork(dir, "request", "deny", egressInputs{Protocol: "tcp", Target: "np-wrong", Phase: "healthy"})
			if err != nil || actual != scenario.want {
				t.Fatalf("got %s %s %v; want %s", actual, reason, err, scenario.want)
			}
		})
	}
}

func TestKernelDropMustMatchSourceInterfaceAndDestination(t *testing.T) {
	for _, bad := range []string{"", "source", "interface", "destination", "reason", "unfinished"} {
		t.Run(bad, func(t *testing.T) {
			dir := t.TempDir()
			e := enforcementEvidence{ID: "test", SourceIP: "10.0.0.2", Interface: "cali123", Address: "192.0.2.5:9001"}
			data, _ := json.Marshal(e)
			if err := os.WriteFile(filepath.Join(dir, "enforcement.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			p := probeRecord{Event: "netfilter-drop", Remote: "10.0.0.2:44000", Destination: e.Address, Interface: e.Interface, Reason: "NETFILTER_DROP"}
			switch bad {
			case "source":
				p.Remote = "10.0.0.3:44000"
			case "interface":
				p.Interface = "cali456"
			case "destination":
				p.Destination = "192.0.2.8:9001"
			case "reason":
				p.Reason = "NO_SOCKET"
			}
			data, _ = json.Marshal(p)
			data = append([]byte("{\"event\":\"drops-ready\"}\n"), data...)
			if bad != "unfinished" {
				data = append(data, []byte("\n{\"event\":\"drops-complete\"}\n")...)
			}
			if err := os.WriteFile(filepath.Join(dir, "drops.jsonl"), data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := checkEnforcement(dir, "test", e.SourceIP); (err == nil) != (bad == "") {
				t.Fatalf("%s: %v", bad, err)
			}
		})
	}
}
