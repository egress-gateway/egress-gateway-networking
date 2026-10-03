package suite

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPreparationEvidenceRejectsMissingEffectsAndUnsafeExecution(t *testing.T) {
	for _, change := range []string{"valid", "unprivileged", "extra-capability", "ipv6-enabled", "wrong-id", "resident-first", "failed-init", "missing-capture", "missing-ipv6-rules"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
			prep := testNamespaceState("case", now)
			prep.UID, prep.GID = 0, 0
			for _, key := range []string{"CapEff", "CapPrm", "CapBnd"} {
				prep.Identity[key] = "3000"
			}
			switch change {
			case "unprivileged":
				prep.Identity["CapEff"] = "0"
			case "extra-capability":
				prep.Identity["CapBnd"] = "203000"
			case "ipv6-enabled":
				prep.DisableIPv6["lo"] = "0"
			case "wrong-id":
				prep.ID = "unrelated"
			}
			writeTestEvidence(t, filepath.Join(dir, "preparation"), "network-state.json", prep)
			initExit := 0
			residentStart := now.Add(2 * time.Second)
			if change == "failed-init" {
				initExit = 1
			}
			if change == "resident-first" {
				residentStart = now
			}
			writeTestEvidence(t, dir, "pod.json", map[string]any{"uid": "pod", "containers": []any{
				map[string]any{"name": "prepare-network", "state": map[string]any{"terminated": map[string]any{"exitCode": initExit, "startedAt": now, "finishedAt": now.Add(time.Second)}}},
				map[string]any{"name": "first-probe", "state": map[string]any{"terminated": map[string]any{"exitCode": 0, "startedAt": now.Add(time.Second), "finishedAt": now.Add(2 * time.Second)}}},
				map[string]any{"name": "probe", "state": map[string]any{"running": map[string]any{"startedAt": residentStart}}},
				map[string]any{"name": "istio-proxy", "state": map[string]any{"running": map[string]any{"startedAt": residentStart}}},
			}})
			for file, text := range map[string]string{
				"capture-rules.txt":    "-A OUTPUT -j ISTIO_OUTPUT\n-A ISTIO_OUTPUT -m owner --uid-owner 10000 -j RETURN\n",
				"preparation-ipv4.txt": "-A OUTPUT -d 127.0.0.1/32 -j NETWORKING_PREP\n-A NETWORKING_PREP -p tcp -m tcp --dport 19091 -j REJECT\n",
				"preparation-ipv6.txt": "-A OUTPUT -d ::1/128 -j NETWORKING_PREP\n-A NETWORKING_PREP -p tcp -m tcp --dport 19091 -j REJECT\n",
			} {
				if change == "missing-capture" && file == "capture-rules.txt" || change == "missing-ipv6-rules" && file == "preparation-ipv6.txt" {
					text = ""
				}
				if err := os.WriteFile(filepath.Join(dir, file), []byte(text), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := checkNetworkPreparation(dir, "case"); (err == nil) != (change == "valid") {
				t.Fatalf("accepted=%t: %v", err == nil, err)
			}
		})
	}
}

func TestIntegrationChainEvidenceRequiresUnchangedFoundationAndRealRestart(t *testing.T) {
	for _, change := range []string{"valid", "foundation-changed", "missing-plugin", "extra-plugin", "not-restored", "no-restart", "wrong-image", "not-ready"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			base := []any{map[string]any{"type": "calico", "policy_setup_timeout_seconds": 10}, map[string]any{"type": "tuning"}, map[string]any{"type": "portmap"}}
			writeTestEvidence(t, dir, "cni-before.json", map[string]any{"plugins": base})
			for _, stage := range []string{"initial", "restarted", "final", "restored"} {
				plugins := append([]any{}, base...)
				if stage != "restored" || change == "not-restored" {
					plugins = append(plugins, map[string]any{"type": "istio-cni", "ambient_enabled": false, "native_nftables": false})
				}
				if stage == "restarted" {
					switch change {
					case "foundation-changed":
						plugins[0] = map[string]any{"type": "calico", "policy_setup_timeout_seconds": 0}
					case "missing-plugin":
						plugins = plugins[:3]
					case "extra-plugin":
						plugins = append(plugins, map[string]any{"type": "other"})
					}
				}
				writeTestEvidence(t, dir, "cni-"+stage+".json", map[string]any{"plugins": plugins})
				image := "docker.io/istio/install-cni:1.31.0@sha256:8cef43ba08ae1af846d0e474591f625cd2dd6b2c0df0efcb17faef0d978ef246"
				if change == "wrong-image" {
					image = "other"
				}
				uid := stage
				if change == "no-restart" {
					uid = "initial"
				}
				writeTestEvidence(t, dir, "cni-agent-"+stage+".json", []any{map[string]any{"uid": uid, "requestedImage": image, "containers": []any{map[string]any{"image": image, "imageID": "digest", "ready": change != "not-ready"}}}})
			}
			if err := checkIntegrationChains(dir); (err == nil) != (change == "valid") {
				t.Fatalf("accepted=%t: %v", err == nil, err)
			}
		})
	}
}

func TestPreparationDropsRequireBothExecutionStages(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	e := enforcementEvidence{SourceIP: "10.0.0.2", Interface: "cali123", Address: "192.0.2.1:9000"}
	for _, change := range []string{"valid", "preparation-not-emitted", "business-not-emitted", "outside-attempt", "other-endpoint"} {
		t.Run(change, func(t *testing.T) {
			probes := []probeRecord{
				{ID: "case", UID: 0, Protocol: "tcp", Attempted: true, Target: e.Address, Started: now, Finished: now.Add(time.Second)},
				{ID: "case", UID: 10000, Protocol: "tcp", Attempted: true, Target: e.Address, Started: now.Add(2 * time.Second), Finished: now.Add(3 * time.Second)},
			}
			drop := probeRecord{Event: "netfilter-drop", Reason: "NETFILTER_DROP", Remote: "10.0.0.2:40000", Destination: e.Address, Interface: e.Interface, Time: now.Add(time.Millisecond)}
			drops := []probeRecord{drop, drop}
			drops[1].Time = now.Add(2*time.Second + time.Millisecond)
			switch change {
			case "preparation-not-emitted":
				drops = drops[1:]
			case "business-not-emitted":
				drops = drops[:1]
			case "outside-attempt":
				drops[0].Time = now.Add(-time.Second)
			case "other-endpoint":
				drops[0].Interface = "caliOther"
			}
			if err := checkPreparationDrops(probes, drops, e, "case"); (err == nil) != (change == "valid") {
				t.Fatalf("accepted=%t: %v", err == nil, err)
			}
		})
	}
}
