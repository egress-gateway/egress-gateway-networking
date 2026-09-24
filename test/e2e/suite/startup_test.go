package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBlockedStartupRequiresExplicitPolicyRefusalAndNoExecution(t *testing.T) {
	for _, change := range []string{"valid", "image", "scheduling", "wrong-pod", "early", "started", "short", "missing", "loss"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			start := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
			f := networkFacts{PolicyWait: 10, FaultStart: start, FaultEnd: start.Add(45 * time.Second)}
			if change == "short" {
				f.FaultEnd = start.Add(8 * time.Second)
			}
			pod := map[string]any{"uid": "pod-1", "created": start.Add(time.Second), "node": "node-1", "conditions": []map[string]string{{"Type": "PodScheduled", "Status": "True"}, {"Type": "PodReadyToStartContainers", "Status": "False"}}}
			if change == "started" {
				pod["containers"] = []map[string]any{{"containerID": "containerd://already-ran"}}
			}
			if change == "scheduling" {
				pod["node"] = ""
			}
			event := map[string]any{"uid": "pod-1", "reason": "FailedCreatePodSandBox", "message": "failed to setup network: plugin calico failed: policy setup timed out", "time": start.Add(20 * time.Second)}
			if change == "image" {
				event["reason"] = "Failed"
				event["message"] = "image pull failed"
			}
			if change == "wrong-pod" {
				event["uid"] = "other"
			}
			if change == "early" {
				event["time"] = start.Add(2 * time.Second)
			}
			for name, value := range map[string]any{"startup.json": pod, "startup-events.json": []any{event}} {
				b, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if change == "missing" && name == "startup-events.json" {
					continue
				}
				if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			packets := "{\"event\":\"capture-ready\"}\n{\"event\":\"network-packet\",\"remote\":\"10.0.0.1:1\"}\n{\"event\":\"network-packet\",\"remote\":\"10.0.0.1:2\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"kernel_packets\":2,\"captured\":2}\n"
			if change == "loss" {
				packets = "{\"event\":\"capture-ready\"}\n"
			}
			for name, body := range map[string]string{
				"packets.jsonl": packets,
				"receiver.log":  "{\"id\":\"x-control-before\",\"remote\":\"10.0.0.1:1\"}\n{\"id\":\"x-control-after\",\"remote\":\"10.0.0.1:2\"}\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, reason, err := evaluateBlockedStartup(dir, "x", f)
			if (result == Satisfied && err == nil) != (change == "valid") {
				t.Fatalf("result=%s %s %v", result, reason, err)
			}
		})
	}
}
