package suite

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEvidence(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func faultEvidence(t *testing.T) (string, map[string]any) {
	t.Helper()
	dir := t.TempDir()
	for _, part := range []string{"before", "after"} {
		writeEvidence(t, dir, "control-"+part+".jsonl", fmt.Sprintf(`{"id":"x-control-%s","attempted":true,"success":true}`, part))
	}
	writeEvidence(t, dir, "probe.jsonl", `{"id":"x","attempted":true,"success":true,"started":"2026-01-01T00:00:01Z"}`)
	writeEvidence(t, dir, "receiver.log", "")
	writeEvidence(t, dir, "recovery.jsonl", recoveryRecord("x-recovery", 3)+recoveryRecord("x-recovery", 4))
	writeRecoveryHops(t, dir, "x-recovery", 2)
	return dir, map[string]any{
		"id": "x", "protocol": "http", "target": "routed", "client": "workload", "phase": "gateway-down",
		"fault_start": "2026-01-01T00:00:00Z", "fault_end": "2026-01-01T00:00:02Z",
		"fault_verified": true, "restored": true, "receiver_stable": true,
	}
}

func writeFacts(t *testing.T, dir string, facts map[string]any) {
	t.Helper()
	body, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	writeEvidence(t, dir, "facts.json", string(body))
}

func recoveryRecord(id string, second int) string {
	return fmt.Sprintf("{\"id\":%q,\"protocol\":\"http\",\"attempted\":true,\"success\":true,\"started\":\"2026-01-01T00:00:%02dZ\",\"finished\":\"2026-01-01T00:00:%02d.1Z\"}\n", id, second, second)
}

func writeRecoveryHops(t *testing.T, dir, id string, count int) {
	t.Helper()
	writeEvidence(t, dir, "workload.log", strings.Repeat(fmt.Sprintf("{\"test_id\":%q,\"upstream_cluster\":\"outbound|15443||gateway.networking-gateway.svc.cluster.local\",\"upstream_tls\":\"TLSv1.3\",\"upstream_peer\":\"spiffe://cluster.local/ns/networking-gateway/sa/gateway\",\"upstream_local\":\"10.0.0.1:1234\"}\n", id), count))
	writeEvidence(t, dir, "gateway.log", strings.Repeat(fmt.Sprintf("{\"test_id\":%q,\"downstream_remote\":\"10.0.0.1:1234\",\"downstream_tls\":\"TLSv1.3\",\"downstream_peer\":\"spiffe://cluster.local/ns/networking-egress/sa/workload\"}\n", id), count))
}

func TestIncompleteFaultFactsCannotPass(t *testing.T) {
	for _, field := range []string{"id", "phase", "fault_start", "fault_end"} {
		t.Run(field, func(t *testing.T) {
			dir, facts := faultEvidence(t)
			delete(facts, field)
			writeFacts(t, dir, facts)
			status, reason, err := evaluateEgress(dir, "x", "allow", egressInputs{Protocol: "http", Target: "routed", Client: "workload", Phase: "gateway-down"})
			if err == nil && status == Satisfied {
				t.Fatalf("incomplete facts passed: %s", reason)
			}
		})
	}
}

func TestMixedRecoveryAttemptsCannotPass(t *testing.T) {
	dir, facts := faultEvidence(t)
	writeFacts(t, dir, facts)
	writeEvidence(t, dir, "recovery.jsonl", recoveryRecord("x-recovery", 3)+recoveryRecord("other-recovery", 4)+recoveryRecord("other-recovery", 5))
	writeRecoveryHops(t, dir, "x-recovery", 1)
	status, reason, err := evaluateEgress(dir, "x", "allow", egressInputs{Protocol: "http", Target: "routed", Client: "workload", Phase: "gateway-down"})
	if err == nil && status == Satisfied {
		t.Fatalf("mixed recovery attempts passed: %s", reason)
	}
}

func TestRecoveryRequiresCurrentOrderedAttempts(t *testing.T) {
	for _, tc := range []struct {
		name, records string
		want          string
	}{
		{"two successes", recoveryRecord("x-recovery", 3) + recoveryRecord("x-recovery", 4), Satisfied},
		{"retry then two successes", strings.ReplaceAll(recoveryRecord("x-recovery", 2), `"success":true`, `"success":false`) + recoveryRecord("x-recovery", 3) + recoveryRecord("x-recovery", 4), Satisfied},
		{"no attempt", strings.ReplaceAll(recoveryRecord("x-recovery", 3), `"attempted":true`, `"attempted":false`) + recoveryRecord("x-recovery", 4), ExecutionError},
		{"wrong protocol", strings.ReplaceAll(recoveryRecord("x-recovery", 3), `"http"`, `"tcp"`) + recoveryRecord("x-recovery", 4), ExecutionError},
		{"missing timestamp", `{"id":"x-recovery","protocol":"http","attempted":true,"success":true}` + "\n" + recoveryRecord("x-recovery", 4), ExecutionError},
		{"before fault ended", recoveryRecord("x-recovery", 1) + recoveryRecord("x-recovery", 4), ExecutionError},
		{"reordered", recoveryRecord("x-recovery", 4) + recoveryRecord("x-recovery", 3), ExecutionError},
		{"failed tail", recoveryRecord("x-recovery", 3) + strings.ReplaceAll(recoveryRecord("x-recovery", 4), `"success":true`, `"success":false`), ExecutionError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, facts := faultEvidence(t)
			writeFacts(t, dir, facts)
			writeEvidence(t, dir, "recovery.jsonl", tc.records)
			status, reason, err := evaluateEgress(dir, "x", "allow", egressInputs{Protocol: "http", Target: "routed", Client: "workload", Phase: "gateway-down"})
			if err != nil || status != tc.want {
				t.Fatalf("status=%s want=%s reason=%s err=%v", status, tc.want, reason, err)
			}
		})
	}
}

func TestFactsCannotDowngradeRequestedCase(t *testing.T) {
	for _, tc := range []struct{ field, value string }{
		{"id", "other"}, {"phase", "healthy"}, {"client", "plain"}, {"target", "external"}, {"protocol", "tcp"},
		{"fault_start", "invalid"}, {"fault_end", "2025-01-01T00:00:00Z"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			dir, facts := faultEvidence(t)
			facts[tc.field] = tc.value
			writeFacts(t, dir, facts)
			status, reason, err := evaluateEgress(dir, "x", "allow", egressInputs{Protocol: "http", Target: "routed", Client: "workload", Phase: "gateway-down"})
			if err != nil || status != ExecutionError {
				t.Fatalf("status=%s reason=%s err=%v", status, reason, err)
			}
		})
	}
}

func TestFaultRequiresProbeInsideWindow(t *testing.T) {
	dir, facts := faultEvidence(t)
	writeFacts(t, dir, facts)
	writeEvidence(t, dir, "probe.jsonl", `{"id":"x","attempted":true,"success":true,"started":"2025-01-01T00:00:01Z"}`)
	status, reason, err := evaluateEgress(dir, "x", "allow", egressInputs{Protocol: "http", Target: "routed", Client: "workload", Phase: "gateway-down"})
	if err != nil || status != Inconclusive {
		t.Fatalf("status=%s reason=%s err=%v", status, reason, err)
	}
}

func TestStartupRecoveryRequiresWindowAndCurrentAttempt(t *testing.T) {
	for _, tc := range []struct{ name, id, end, want string }{
		{"valid", "x-recovered", "2026-01-01T00:00:02Z", Satisfied},
		{"missing window", "x-recovered", "", ExecutionError},
		{"other attempt", "other-recovered", "2026-01-01T00:00:02Z", ExecutionError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, facts := faultEvidence(t)
			facts["phase"], facts["startup_blocked"], facts["fault_end"] = "repair", true, tc.end
			writeFacts(t, dir, facts)
			writeEvidence(t, dir, "recovered.jsonl", recoveryRecord(tc.id, 3))
			writeRecoveryHops(t, dir, "x-recovered", 1)
			status, reason, err := evaluateEgress(dir, "x", "startup", egressInputs{Protocol: "http", Target: "routed", Client: "workload", Phase: "repair"})
			if err != nil || status != tc.want {
				t.Fatalf("status=%s want=%s reason=%s err=%v", status, tc.want, reason, err)
			}
		})
	}
}
