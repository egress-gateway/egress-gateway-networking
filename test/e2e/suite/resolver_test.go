package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestResolverPermissionAndRequestedTransportAreSeparate(t *testing.T) {
	for _, variant := range []string{"both-permitted", "missing-tcp", "wrong-receiver", "wrong-query", "recovery-missing", "other-resolver-isolated", "other-resolver-delivered", "other-resolver-unobserved", "revoked"} {
		t.Run(variant, func(t *testing.T) {
			dir, f := dnsFixture(t)
			write := func(name string, v any) {
				t.Helper()
				data, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.Mode = "resolver-direct"
			if strings.HasPrefix(variant, "other-resolver-") {
				f.Mode = "resolver-direct-other"
			}
			if variant == "revoked" {
				f.Mode = "resolver-direct-revoked"
			}
			f.Transport = "tcp"
			f.Captures = append(f.Captures, "receiver-external.jsonl")
			write("dns-facts.json", f)
			q := dnsExchange{ID: "case", Name: f.Name, Type: 1, Transport: "tcp", Attempted: true, Sent: true, Received: true, Correlated: true, RCODE: "RCodeSuccess", Answers: []string{"192.0.2.1"}}
			if variant == "wrong-query" {
				q.ID = "other"
			}
			write("query.json", q)
			q.ID = "case-recovery"
			write("recovery.json", q)
			packets := []string{`{"event":"capture-ready"}`, `{"event":"network-packet","protocol":"udp","remote":"10.1.2.3:1234","destination":"172.18.0.3:53"}`}
			if variant != "missing-tcp" {
				packets = append(packets, `{"event":"network-packet","protocol":"tcp","remote":"10.1.2.3:4321","destination":"172.18.0.3:53"}`)
			}
			if variant == "wrong-receiver" {
				packets = append(packets, `{"event":"network-packet","protocol":"tcp","remote":"10.1.2.3:4321","destination":"172.18.0.4:53"}`)
			}
			n := len(packets) - 1
			end, _ := json.Marshal(map[string]any{"event": "capture-complete", "dropped": 0, "captured": n, "kernel_packets": n})
			packets = append(packets, string(end))
			if err := os.WriteFile(filepath.Join(dir, "receiver-external.jsonl"), []byte(strings.Join(packets, "\n")), 0600); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(variant, "other-resolver-") {
				source := slices.Clone(packets[:len(packets)-1])
				if variant != "other-resolver-unobserved" {
					source = append(source, `{"event":"network-packet","protocol":"tcp","remote":"10.1.2.3:45678","destination":"10.1.2.4:53"}`)
				}
				end, _ := json.Marshal(map[string]any{"event": "capture-complete", "dropped": 0, "captured": len(source) - 1, "kernel_packets": len(source) - 1})
				source = append(source, string(end))
				if err := os.WriteFile(filepath.Join(dir, "source-dns.jsonl"), []byte(strings.Join(source, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
				f.DropFiles = []string{"drops.jsonl"}
				write("dns-facts.json", f)
				if err := os.WriteFile(filepath.Join(dir, "drops.jsonl"), []byte("{\"event\":\"drops-ready\"}\n{\"event\":\"netfilter-drop\",\"remote\":\"10.1.2.3:45678\",\"destination\":\"10.1.2.4:53\",\"reason\":\"NETFILTER_DROP\",\"interface\":\"cali123\"}\n{\"event\":\"drops-complete\"}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if variant == "other-resolver-delivered" {
				forbidden := strings.ReplaceAll(strings.Join(packets, "\n"), "172.18.0.3:53", "10.1.2.4:53")
				if err := os.WriteFile(filepath.Join(dir, "receiver-dns.jsonl"), []byte(forbidden), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "external.log"), []byte(`{"event":"received","protocol":"dns","id":"case","remote":"10.1.2.3:4321"}`), 0600); err != nil {
				t.Fatal(err)
			}
			if variant != "recovery-missing" {
				child, _ := dnsFixture(t)
				destination := filepath.Join(dir, "recovery-isolation")
				if err := os.Mkdir(destination, 0700); err != nil {
					t.Fatal(err)
				}
				files, err := os.ReadDir(child)
				if err != nil {
					t.Fatal(err)
				}
				for _, file := range files {
					data, err := os.ReadFile(filepath.Join(child, file.Name()))
					if err != nil {
						t.Fatal(err)
					}
					data = []byte(strings.ReplaceAll(string(data), "case", "case-recovery-isolation"))
					if err = os.WriteFile(filepath.Join(destination, file.Name()), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			actual, _, reason, err := evaluateDNS(dir, "case")
			if variant == "both-permitted" || variant == "other-resolver-isolated" {
				if err != nil || actual != Satisfied {
					t.Fatalf("%s %s %v", actual, reason, err)
				}
			} else if err == nil && actual == Satisfied {
				t.Fatalf("accepted %s", variant)
			}
		})
	}
}
