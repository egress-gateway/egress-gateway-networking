package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testNamespaceState(id string, now time.Time) namespaceState {
	return namespaceState{ID: id, Event: "network-state", UID: 10000, GID: 10000, Started: now, Finished: now, Identity: map[string]string{"Uid": "10000 10000 10000 10000", "Gid": "10000 10000 10000 10000", "CapInh": "0", "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0", "NoNewPrivs": "1", "Seccomp": "2"}, Addresses: map[string][]string{"lo": {"127.0.0.1/8"}, "eth0": {"10.0.0.2/32"}}, DisableIPv6: map[string]string{"all": "1", "default": "1", "lo": "1", "eth0": "1"}, Files: map[string]string{"/proc/net/if_inet6": "", "/proc/net/ipv6_route": ""}}
}

func writeTestEvidence(t *testing.T, dir, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestIPv6RequiresDisabledStateAndRealUnavailability(t *testing.T) {
	for _, scenario := range []string{"disabled", "enabled-loopback", "link-local", "usable-route", "missing-route", "refused-listener", "missing-attempt", "ipv4-down"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now().UTC()
			id := "request"
			writeTestEvidence(t, dir, "pod.json", map[string]any{"uid": "pod-uid", "created": now, "ip": "10.0.0.2"})
			for _, stage := range []string{"first-init", "app"} {
				path := filepath.Join(dir, stage)
				state := testNamespaceState(id, now)
				if stage == "first-init" {
					switch scenario {
					case "enabled-loopback":
						state.DisableIPv6["lo"] = "0"
					case "link-local":
						state.Addresses["eth0"] = append(state.Addresses["eth0"], "fe80::1/64")
					case "usable-route":
						state.Files["/proc/net/ipv6_route"] = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 0 0 00000001 eth0"
					case "missing-route":
						delete(state.Files, "/proc/net/ipv6_route")
					}
				}
				writeTestEvidence(t, path, "network-state.json", state)
				var lines []string
				for _, key := range []string{"tcp6 [::1]:19091", "tcp6 [fe80::ecee:eeff:feee:eeee%eth0]:19091", "udp6 [::1]:19091", "udp6 [fe80::ecee:eeff:feee:eeee%eth0]:19091", "listen-tcp6 [::1]:0"} {
					protocol, target, _ := strings.Cut(key, " ")
					errno := 99
					if scenario == "refused-listener" {
						errno = 111
					}
					p := probeRecord{ID: id, Event: "ipv6-attempt", UID: 10000, Protocol: protocol, Target: target, Attempted: true, Started: now, Finished: now, SocketError: errno}
					b, err := json.Marshal(p)
					if err != nil {
						t.Fatal(err)
					}
					lines = append(lines, string(b))
				}
				if scenario == "missing-attempt" {
					lines = lines[1:]
				}
				if err := os.WriteFile(filepath.Join(path, "probe.jsonl"), []byte(strings.Join(lines, "\n")), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeTestEvidence(t, dir, "ipv4.jsonl", probeRecord{ID: id + "-ipv4", UID: 10000, Attempted: true, Success: scenario != "ipv4-down"})
			result, reason, err := evaluateIPv6Execution(dir, id)
			if err != nil || (result == Satisfied) != (scenario == "disabled") {
				t.Fatalf("%s: %s, %v", result, reason, err)
			}
		})
	}
}
