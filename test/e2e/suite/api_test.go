package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAPIDenialNeedsPostTranslationDropAndHealthyControl(t *testing.T) {
	for _, scenario := range []string{"matched", "wrong-source-port", "wrong-endpoint", "outside-attempt", "control-failed", "connected", "policy-widened"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now().UTC()
			id := "request"
			address := "10.96.0.1:443"
			endpoint := "192.0.2.1:6443"
			writeTestEvidence(t, dir, "api.json", map[string]any{"id": id, "phase": "deny", "target": "api-service", "address": address, "endpoint": endpoint, "source": "10.0.0.2", "interface": "cali123"})
			writeTestEvidence(t, dir, "api-service.json", core.Service{ObjectMeta: meta.ObjectMeta{Name: "kubernetes", Namespace: "default"}, Spec: core.ServiceSpec{ClusterIP: "10.96.0.1", Ports: []core.ServicePort{{Port: 443, Protocol: core.ProtocolTCP}}}})
			writeTestEvidence(t, dir, "api-endpoints.json", discovery.EndpointSliceList{Items: []discovery.EndpointSlice{{ObjectMeta: meta.ObjectMeta{Namespace: "default", Labels: map[string]string{"kubernetes.io/service-name": "kubernetes"}}, Ports: []discovery.EndpointPort{{Port: new(int32(6443)), Protocol: new(core.ProtocolTCP)}}, Endpoints: []discovery.Endpoint{{Addresses: []string{"192.0.2.1"}, Conditions: discovery.EndpointConditions{Ready: new(true)}}}}}})
			n := enrollment.Network{Namespace: "networking-np", Binding: "np"}
			if scenario == "policy-widened" {
				n.Forward = []enrollment.TCPDestination{{Peer: enrollment.Peer{IPv4: "192.0.2.1"}, Ports: []int32{6443}}}
			}
			p, err := enrollment.ExpandPolicy(n)
			if err != nil {
				t.Fatal(err)
			}
			writeTestEvidence(t, dir, "effective-policy.json", network.NetworkPolicy{ObjectMeta: meta.ObjectMeta{Name: "api-case", Namespace: "networking-np"}, Spec: p.Spec})
			for _, part := range []string{"before", "after"} {
				writeTestEvidence(t, dir, "control-"+part+".jsonl", probeRecord{ID: id + "-control-" + part, Attempted: true, Success: scenario != "control-failed", Target: address})
			}
			writeTestEvidence(t, dir, "probe.jsonl", probeRecord{ID: id, UID: 10000, Attempted: true, Protocol: "tcp", Target: address, Local: "10.0.0.2:40000", Started: now, Finished: now.Add(time.Second), Connected: scenario == "connected"})
			drop := probeRecord{Event: "netfilter-drop", Reason: "NETFILTER_DROP", Remote: "10.0.0.2:40000", Destination: endpoint, Interface: "cali123", Time: now.Add(time.Millisecond)}
			switch scenario {
			case "wrong-source-port":
				drop.Remote = "10.0.0.2:40001"
			case "wrong-endpoint":
				drop.Destination = address
			case "outside-attempt":
				drop.Time = now.Add(-time.Second)
			}
			var lines []string
			for _, record := range []probeRecord{{Event: "drops-ready", Target: endpoint}, drop, {Event: "drops-complete"}} {
				b, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				lines = append(lines, string(b))
			}
			if err := os.WriteFile(filepath.Join(dir, "drops.jsonl"), []byte(strings.Join(lines, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}
			result, reason, err := evaluateAPI(dir, id, "api-endpoint", egressInputs{Protocol: "tcp", Target: "api-service", Phase: "deny"})
			if err != nil || (result == Satisfied) != (scenario == "matched") {
				t.Fatalf("%s: %s, %v", result, reason, err)
			}
		})
	}
}
