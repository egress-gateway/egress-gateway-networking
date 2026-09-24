package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayBackgroundNeedsPreciseNATAndCaseOwnership(t *testing.T) {
	for _, change := range []string{"valid", "wrong-case", "protected-source", "other-namespace", "other-account", "no-uid", "other-original-source", "other-destination", "other-reply-source", "other-port", "no-map", "udp", "other-packet-destination", "partial-map"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			owner := map[string]string{"ID": "case", "Namespace": "networking-gateway", "ServiceAccount": "gateway", "UID": "pod-1", "IP": "10.0.0.2", "Destination": "192.0.2.10:8080"}
			table := "tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=192.0.2.10 sport=41234 dport=8080 src=192.0.2.10 dst=192.0.2.1 sport=8080 dport=50000 [ASSURED] mark=0 use=1\n"
			packet := probeRecord{Protocol: "tcp", Remote: "192.0.2.1:50000", Destination: owner["Destination"]}
			switch change {
			case "wrong-case":
				owner["ID"] = "old-case"
			case "protected-source":
				owner["IP"] = "10.0.0.1"
			case "other-namespace":
				owner["Namespace"] = "other"
			case "other-account":
				owner["ServiceAccount"] = "workload"
			case "no-uid":
				owner["UID"] = ""
			case "other-original-source":
				table = strings.ReplaceAll(table, "src=10.0.0.2", "src=10.0.0.1")
			case "other-destination":
				table = strings.ReplaceAll(table, "dst=192.0.2.10", "dst=192.0.2.20")
			case "other-reply-source":
				table = strings.ReplaceAll(table, "src=192.0.2.10", "src=192.0.2.20")
			case "other-port":
				packet.Remote = "192.0.2.1:50001"
			case "udp":
				packet.Protocol = "udp"
			case "other-packet-destination":
				packet.Destination = "192.0.2.20:8080"
			case "partial-map":
				table = "tcp src=10.0.0.2 dst=192.0.2.10 sport=41234 dport=8080"
			}
			b, err := json.Marshal(owner)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "gateway-flow-owner.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			if change != "no-map" {
				if err := os.WriteFile(filepath.Join(dir, "gateway-conntrack-before.txt"), []byte(table), 0600); err != nil {
					t.Fatal(err)
				}
			}
			matched, err := gatewayBackgroundFlow(dir, "case", "10.0.0.1", packet)
			if matched != (change == "valid") {
				t.Fatalf("matched=%t err=%v", matched, err)
			}
		})
	}
}

func TestCalicoDenialKeepsUnknownAndProtectedTrafficUnsafe(t *testing.T) {
	for _, tc := range []struct{ name, remote, receiver, want string }{
		{"owned gateway", "192.0.2.1:50000", "", Satisfied},
		{"unknown translated connection", "192.0.2.1:50001", "", Inconclusive},
		{"protected source packet", "10.0.0.1:40000", "", Violated},
		{"current request delivered", "192.0.2.1:50000", `{"event":"received","id":"x","remote":"192.0.2.1:50000"}`, Violated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"profile":                      "calico-istio",
				"facts.json":                   `{"id":"x","protocol":"tcp","target":"external","client":"workload","phase":"healthy","source_ip":"10.0.0.1","fault_verified":true,"restored":true,"receiver_stable":true}`,
				"control-before.jsonl":         `{"id":"x-control-before","attempted":true,"success":true}`,
				"control-after.jsonl":          `{"id":"x-control-after","attempted":true,"success":true}`,
				"probe.jsonl":                  `{"id":"x","attempted":true,"success":false,"local":"10.0.0.1:40000"}`,
				"receiver.log":                 "{\"event\":\"received\",\"id\":\"x-control-before\",\"remote\":\"192.0.2.2:1\"}\n{\"event\":\"received\",\"id\":\"x-control-after\",\"remote\":\"192.0.2.2:2\"}\n" + tc.receiver + "\n",
				"gateway-flow-owner.json":      `{"id":"x","namespace":"networking-gateway","serviceAccount":"gateway","uid":"pod1","ip":"10.0.0.2","destination":"192.0.2.10:8080"}`,
				"gateway-conntrack-before.txt": "tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=192.0.2.10 sport=41234 dport=8080 src=192.0.2.10 dst=192.0.2.1 sport=8080 dport=50000 [ASSURED]\n",
				"enforcement.json":             `{"id":"x","source_ip":"10.0.0.1","interface":"cali1","address":"192.0.2.10:8080"}`,
				"drops.jsonl":                  "{\"event\":\"drops-ready\"}\n{\"event\":\"netfilter-drop\",\"reason\":\"NETFILTER_DROP\",\"remote\":\"10.0.0.1:40000\",\"destination\":\"192.0.2.10:8080\",\"interface\":\"cali1\"}\n{\"event\":\"drops-complete\"}\n",
			}
			ps := []probeRecord{{Event: "capture-ready"}, {Event: "network-packet", Remote: "192.0.2.2:1"}, {Event: "network-packet", Remote: "192.0.2.2:2"}, {Event: "network-packet", Protocol: "tcp", Remote: tc.remote, Destination: "192.0.2.10:8080"}, {Event: "capture-complete", Dropped: new(uint32(0)), Captured: new(uint32(3)), KernelPackets: new(uint32(3))}}
			for _, p := range ps {
				b, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				files["packets.jsonl"] += string(b) + "\n"
			}
			for name, body := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, reason, err := evaluateEgress(dir, "x", "deny", egressInputs{Protocol: "tcp", Target: "external", Client: "workload", Phase: "healthy"})
			if err != nil || got != tc.want {
				t.Fatalf("got %s (%s) %v; want %s", got, reason, err, tc.want)
			}
		})
	}
}
