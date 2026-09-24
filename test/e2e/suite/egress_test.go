package suite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMalformedEvidenceCannotPass(t *testing.T) {
	for _, contract := range []string{"allow", "deny"} {
		t.Run(contract, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"facts.json":           `{"id":"x","protocol":"http","target":"external","client":"workload","phase":"healthy","source_ip":"10.0.0.1","fault_verified":true,"restored":true,"receiver_stable":true}`,
				"control-before.jsonl": `{"id":"x-control-before","attempted":true,"success":true}`,
				"control-after.jsonl":  `{"id":"x-control-after","attempted":true,"success":true}`,
				"probe.jsonl":          `{"id":"x","attempted":true,"success":false,"local":"10.0.0.1:1"}`,
				"receiver.log":         "plain receiver diagnostic\n{\"event\":\"received\",\"id\":\"x-control-before\",\"remote\":\"10.0.0.2:2\"}\n{\"event\":\"received\",\"id\":\"x-control-after\",\"remote\":\"10.0.0.2:3\"}\n",
				"packets.jsonl":        "{\"event\":\"capture-ready\"}\n{\"event\":\"network-packet\",\"remote\":\"10.0.0.2:2\"}\n{\"event\":\"network-packet\",\"remote\":\"10.0.0.1:1\"\n{\"event\":\"network-packet\",\"remote\":\"10.0.0.2:3\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"kernel_packets\":3,\"captured\":3}\n",
			}
			broken := "packets.jsonl"
			if contract == "allow" {
				files["probe.jsonl"] = "{\"id\":\"x\",\"attempted\":true,\"success\":false\n{\"id\":\"x\",\"attempted\":true,\"success\":true}\n"
				broken = "probe.jsonl"
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			actual, _, err := evaluateEgress(dir, "x", contract, egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
			if err == nil || !strings.Contains(err.Error(), broken) || actual == Satisfied {
				t.Fatalf("corrupt evidence accepted: actual=%s err=%v", actual, err)
			}
		})
	}
}

func TestRecordsAllowPlainReceiverLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receiver.log")
	if err := os.WriteFile(path, []byte("\nplain log line\n [warning] receiver ready\n  {\"event\":\"received\",\"id\":\"x\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := records(path)
	if err != nil || len(r) != 1 || r[0].ID != "x" {
		t.Fatalf("records=%+v err=%v", r, err)
	}
}

func TestNegativeEvidenceRequiresControlsAndAttribution(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("facts.json", `{"id":"probe","protocol":"udp","target":"external","client":"workload","phase":"healthy","fault_verified":true,"restored":true,"receiver_stable":true}`)
	write("control-before.jsonl", `{"id":"probe-control-before","attempted":true,"success":true}`)
	write("control-after.jsonl", `{"id":"probe-control-after","attempted":true,"success":true}`)
	write("probe.jsonl", `{"id":"unrelated","attempted":true,"success":false}`)
	write("receiver.log", `{"event":"received","id":"unrelated"}`)
	status, _, err := evaluateEgress(dir, "probe", "deny", egressInputs{Protocol: "udp", Target: "external", Client: "workload", Phase: "healthy"})
	if err != nil || status != Inconclusive {
		t.Fatalf("unrelated attempt accepted: %s %v", status, err)
	}
	write("probe.jsonl", `{"id":"probe","attempted":true,"success":false,"digest":"packet-hash"}`)
	write("receiver.log", `{"event":"packet","digest":"packet-hash"}`)
	status, _, err = evaluateEgress(dir, "probe", "deny", egressInputs{Protocol: "udp", Target: "external", Client: "workload", Phase: "healthy"})
	if err != nil || status != Violated {
		t.Fatalf("failed handshake hid delivered packet: %s %v", status, err)
	}
	write("control-after.jsonl", `{"id":"probe-control-after","attempted":true,"success":false}`)
	status, _, err = evaluateEgress(dir, "probe", "deny", egressInputs{Protocol: "udp", Target: "external", Client: "workload", Phase: "healthy"})
	if err != nil || status != ExecutionError {
		t.Fatalf("broken receiver control accepted: %s %v", status, err)
	}
}

func TestTimeoutAndMissingObserverCannotCertifyIsolation(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"facts.json":           `{"id":"x","protocol":"http","target":"external","client":"workload","phase":"healthy","fault_verified":true,"restored":true,"receiver_stable":true}`,
		"control-before.jsonl": `{"id":"x-control-before","attempted":true,"success":true}`,
		"control-after.jsonl":  `{"id":"x-control-after","attempted":true,"success":true}`,
		"probe.jsonl":          `{"id":"x","attempted":true,"success":false,"error":"timeout"}`,
		"receiver.log":         "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	status, _, err := evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
	if err != nil || status != Inconclusive {
		t.Fatalf("timeout accepted: %s %v", status, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "packets.jsonl"), []byte("{\"event\":\"capture-ready\"}\n{\"event\":\"capture-complete\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	status, _, err = evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
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
	write("facts.json", `{"id":"x","target":"external","client":"workload","protocol":"http","phase":"healthy","fault_verified":true,"restored":true,"receiver_stable":true}`)
	write("control-before.jsonl", `{"id":"x-control-before","attempted":true,"success":true}`)
	write("control-after.jsonl", `{"id":"x-control-after","attempted":true,"success":true}`)
	write("probe.jsonl", `{"id":"x","attempted":true,"success":true}`)
	write("receiver.log", `{"event":"received","id":"x"}`)
	write("workload.log", `{"test_id":"x","upstream_cluster":"outbound|15443||gateway.networking-gateway.svc.cluster.local","upstream_tls":"TLSv1.3","upstream_peer":"spiffe://cluster.local/ns/networking-gateway/sa/gateway","upstream_local":"10.0.0.1:1234"}`)
	write("gateway.log", `{"test_id":"x","downstream_remote":"10.0.0.1:1234","downstream_tls":"TLSv1.3","downstream_peer":"spiffe://cluster.local/ns/networking-egress/sa/workload"}`)
	status, _, err := evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
	if err != nil || status != Satisfied {
		t.Fatalf("legal gateway path called a bypass: %s %v", status, err)
	}
	write("receiver.log", "")
	status, _, err = evaluateEgress(dir, "x", "gateway", egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
	if err != nil || status != Inconclusive {
		t.Fatalf("pending receiver logs treated as a terminal verdict: %s %v", status, err)
	}
	write("receiver.log", `{"event":"received","id":"x"}`)
	write("workload.log", `{"test_id":"x","upstream_cluster":"PassthroughCluster"}`)
	status, _, err = evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
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
	write("facts.json", `{"id":"x","protocol":"http","target":"external","client":"workload","phase":"healthy","source_ip":"10.0.0.1","fault_verified":true,"restored":true,"receiver_stable":true}`)
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
			status, _, err := evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
			if err != nil || status != tc.want {
				t.Fatalf("got %s %v, want %s", status, err, tc.want)
			}
		})
	}
	write("packets.jsonl", prefix+`{"event":"capture-complete","dropped":0,"kernel_packets":2,"captured":2}`+"\n")
	t.Run("unreadable profile cannot bypass enforcement", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(dir, "profile"), 0700); err != nil {
			t.Fatal(err)
		}
		status, _, err := evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "http", Target: "external", Client: "workload", Phase: "healthy"})
		if err == nil || !strings.Contains(err.Error(), "profile") || status == Satisfied {
			t.Fatalf("unreadable profile accepted: %s %v", status, err)
		}
	})

}

func TestCalicoNodeAcceptedTCPIsDeliveryWithoutApplicationEcho(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"profile":              "calico-istio",
		"facts.json":           `{"id":"x","protocol":"tcp","target":"node","client":"workload","phase":"healthy","source_ip":"10.0.0.1","fault_verified":true,"restored":true,"receiver_stable":true}`,
		"control-before.jsonl": `{"id":"x-control-before","attempted":true,"success":true}`,
		"control-after.jsonl":  `{"id":"x-control-after","attempted":true,"success":true}`,
		"probe.jsonl":          `{"id":"x","attempted":true,"success":false}`,
		"receiver.log":         `{"event":"connection","remote":"10.0.0.1:42424"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, reason, err := evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "tcp", Target: "node", Client: "workload", Phase: "healthy"})
	if err != nil || result != Violated {
		t.Fatalf("accepted TCP concealed: %s %s %v", result, reason, err)
	}
}
