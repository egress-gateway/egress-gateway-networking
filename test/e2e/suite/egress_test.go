package suite

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNegativeEvidenceRequiresControlsAndAttribution(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("facts.json", `{"fault_verified":true,"restored":true,"receiver_stable":true}`)
	write("control-before.jsonl", `{"id":"probe-control-before","attempted":true,"success":true}`)
	write("control-after.jsonl", `{"id":"probe-control-after","attempted":true,"success":true}`)
	write("probe.jsonl", `{"id":"unrelated","attempted":true,"success":false}`)
	write("receiver.log", `{"event":"received","id":"unrelated"}`)
	status, _, err := evaluateEgress(dir, "probe", "deny")
	if err != nil || status != Inconclusive {
		t.Fatalf("unrelated attempt accepted: %s %v", status, err)
	}
	write("probe.jsonl", `{"id":"probe","attempted":true,"success":false,"digest":"packet-hash"}`)
	write("receiver.log", `{"event":"packet","digest":"packet-hash"}`)
	status, _, err = evaluateEgress(dir, "probe", "deny")
	if err != nil || status != Violated {
		t.Fatalf("failed handshake hid delivered packet: %s %v", status, err)
	}
	write("control-after.jsonl", `{"id":"probe-control-after","attempted":true,"success":false}`)
	status, _, err = evaluateEgress(dir, "probe", "deny")
	if err != nil || status != ExecutionError {
		t.Fatalf("broken receiver control accepted: %s %v", status, err)
	}
}

func TestTimeoutAndMissingObserverCannotCertifyIsolation(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"facts.json":           `{"fault_verified":true,"restored":true,"receiver_stable":true}`,
		"control-before.jsonl": `{"id":"x-control-before","attempted":true,"success":true}`,
		"control-after.jsonl":  `{"id":"x-control-after","attempted":true,"success":true}`,
		"probe.jsonl":          `{"id":"x","attempted":true,"success":false,"error":"timeout"}`,
		"receiver.log":         "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	status, _, err := evaluateEgress(dir, "x", "deny")
	if err != nil || status != Inconclusive {
		t.Fatalf("timeout accepted: %s %v", status, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packets.jsonl"), []byte("{\"event\":\"capture-ready\"}\n{\"event\":\"capture-complete\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	status, _, err = evaluateEgress(dir, "x", "deny")
	if err != nil || status != Inconclusive {
		t.Fatalf("unvalidated observer accepted: %s %v", status, err)
	}
}

func TestDirectAddressRoutedThroughGatewayIsNotABypass(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("facts.json", `{"target":"external","client":"workload","protocol":"http","phase":"healthy","fault_verified":true,"restored":true,"receiver_stable":true}`)
	write("control-before.jsonl", `{"id":"x-control-before","attempted":true,"success":true}`)
	write("control-after.jsonl", `{"id":"x-control-after","attempted":true,"success":true}`)
	write("probe.jsonl", `{"id":"x","attempted":true,"success":true}`)
	write("receiver.log", `{"event":"received","id":"x"}`)
	write("workload.log", `{"test_id":"x","upstream_cluster":"outbound|15443||gateway.networking-gateway.svc.cluster.local","upstream_tls":"TLSv1.3","upstream_peer":"spiffe://cluster.local/ns/networking-gateway/sa/gateway","upstream_local":"10.0.0.1:1234"}`)
	write("gateway.log", `{"test_id":"x","downstream_remote":"10.0.0.1:1234","downstream_tls":"TLSv1.3","downstream_peer":"spiffe://cluster.local/ns/networking-egress/sa/workload"}`)
	status, _, err := evaluateEgress(dir, "x", "deny")
	if err != nil || status != Satisfied {
		t.Fatalf("legal gateway path called a bypass: %s %v", status, err)
	}
	write("workload.log", `{"test_id":"x","upstream_cluster":"PassthroughCluster"}`)
	status, _, err = evaluateEgress(dir, "x", "deny")
	if err != nil || status != Violated {
		t.Fatalf("direct delivery hidden: %s %v", status, err)
	}
}

func TestEverySuccessfulHTTPRequestNeedsBothAuthenticatedHops(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"workload.log": `{"test_id":"x","upstream_cluster":"outbound|15443||gateway.networking-gateway.svc.cluster.local","upstream_tls":"TLSv1.3","upstream_peer":"spiffe://cluster.local/ns/networking-gateway/sa/gateway","upstream_local":"10.0.0.1:1234"}`,
		"gateway.log":  `{"test_id":"x","downstream_remote":"10.0.0.1:1234","downstream_tls":"TLSv1.3","downstream_peer":"spiffe://cluster.local/ns/networking-egress/sa/workload"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	probes := []probeRecord{{ID: "x", Attempted: true, Success: true}, {ID: "x", Attempted: true, Success: true}}
	if err := gatewayEvidence(dir, "x", "http", probes); err == nil {
		t.Fatal("one valid hop concealed a request without evidence")
	}
}

func TestDenialNeedsLosslessCompleteObservationAndNeverIgnoresLateTraffic(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("facts.json", `{"source_ip":"10.0.0.1","fault_verified":true,"restored":true,"receiver_stable":true}`)
	write("control-before.jsonl", `{"id":"x-control-before","attempted":true,"success":true}`)
	write("control-after.jsonl", `{"id":"x-control-after","attempted":true,"success":true}`)
	write("probe.jsonl", `{"id":"x","attempted":true,"local":"10.0.0.1:1","success":false,"started":"2026-01-01T00:00:00Z","finished":"2026-01-01T00:00:02Z"}`)
	write("receiver.log", "{\"event\":\"received\",\"id\":\"x-control-before\",\"remote\":\"10.0.0.2:2\"}\n{\"event\":\"received\",\"id\":\"x-control-after\",\"remote\":\"10.0.0.2:3\"}\n")
	prefix := "{\"event\":\"capture-ready\"}\n{\"event\":\"network-packet\",\"remote\":\"10.0.0.2:2\"}\n{\"event\":\"network-packet\",\"remote\":\"10.0.0.2:3\"}\n"
	for _, tc := range []struct{ name, end, extra, want string }{
		{"missing counters", `{"event":"capture-complete"}`, "", Inconclusive},
		{"dropped", `{"event":"capture-complete","dropped":1,"kernel_packets":3,"captured":2}`, "", Inconclusive},
		{"unread", `{"event":"capture-complete","dropped":0,"kernel_packets":3,"captured":2}`, "", Inconclusive},
		{"complete", `{"event":"capture-complete","dropped":0,"kernel_packets":2,"captured":2}`, "", Satisfied},
		{"late packet", `{"event":"capture-complete","dropped":1,"kernel_packets":4,"captured":3}`, `{"event":"network-packet","remote":"10.0.0.1:1","time":"2026-01-01T00:00:10Z"}`, Violated},
		{"late unknown packet", `{"event":"capture-complete","dropped":0,"kernel_packets":3,"captured":3}`, `{"event":"network-packet","remote":"10.0.0.9:9","time":"2026-01-01T00:00:10Z"}`, Inconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write("packets.jsonl", prefix+tc.extra+"\n"+tc.end+"\n")
			status, _, err := evaluateEgress(dir, "x", "deny")
			if err != nil || status != tc.want {
				t.Fatalf("got %s %v, want %s", status, err, tc.want)
			}
		})
	}
}
