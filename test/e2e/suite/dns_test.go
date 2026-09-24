package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func dnsFixture(t *testing.T) (string, dnsFacts) {
	t.Helper()
	dir := t.TempDir()
	write := func(n string, v any) {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	f := dnsFacts{ID: "case", Mode: "unregistered", Name: "case.test.", Source: "10.1.2.3", Type: 1, Transport: "udp", Restored: true, FaultVerified: true, Attempted: true, Controls: []string{"before.json", "after.json"}, Captures: []string{"source-dns.jsonl", "receiver-dns.jsonl"}}
	q := dnsExchange{ID: "case", Name: f.Name, Type: 1, Transport: "udp", Attempted: true, Sent: true, Received: true, Correlated: true, RCODE: "RCodeSuccess", Answers: []string{"240.240.1.1"}}
	write("query.json", q)
	q.ID = "case-control"
	write("before.json", q)
	write("after.json", q)
	for _, name := range f.Captures {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("{\"event\":\"capture-ready\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"captured\":0,\"kernel_packets\":0}\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("dns-tuples.json", map[string]any{"source": f.Source, "endpoints": []string{"10.1.2.4"}, "external": "172.18.0.3"})
	write("dns-facts.json", f)
	return dir, f
}
func TestDNSVerdictSeparatesFunctionAndIsolation(t *testing.T) {
	dir, _ := dnsFixture(t)
	actual, function, _, e := evaluateDNS(dir, "case")
	if e != nil || actual != Satisfied || function != "satisfied" {
		t.Fatalf("%s %s %v", actual, function, e)
	}
	var q dnsExchange
	if e = readDNSJSON(dir, "query.json", &q); e != nil {
		t.Fatal(e)
	}
	q.Answers = []string{"192.0.2.1"}
	b, _ := json.Marshal(q)
	if e = os.WriteFile(filepath.Join(dir, "query.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	actual, function, _, e = evaluateDNS(dir, "case")
	if e != nil || actual != Satisfied || function != "not_satisfied" {
		t.Fatalf("%s %s %v", actual, function, e)
	}
	r := Report{Mode: "enforce", Finished: time.Now(), Cases: []CaseResult{{ID: "D1-01", FunctionalityRequired: true, Actual: actual, Functionality: function}}}
	if r.Accepted() {
		t.Fatal("functional failure hidden by network isolation")
	}
}
func TestDNSIncompleteEvidenceCannotPass(t *testing.T) {
	for _, kind := range []string{"unexecuted", "fault", "recovery", "unhealthy", "drops", "association", "missing"} {
		t.Run(kind, func(t *testing.T) {
			dir, f := dnsFixture(t)
			switch kind {
			case "unexecuted":
				f.Attempted = false
			case "fault":
				f.FaultVerified = false
			case "recovery":
				f.Restored = false
			case "unhealthy":
				if e := os.WriteFile(filepath.Join(dir, "before.json"), []byte(`{"id":"case-control"}`), 0600); e != nil {
					t.Fatal(e)
				}
			case "drops":
				if e := os.WriteFile(filepath.Join(dir, "receiver-dns.jsonl"), []byte("{\"event\":\"capture-ready\"}\n{\"event\":\"capture-complete\",\"dropped\":1,\"captured\":0,\"kernel_packets\":1}\n"), 0600); e != nil {
					t.Fatal(e)
				}
			case "association":
				f.ID = "other"
			case "missing":
				f.Captures = nil
			}
			b, _ := json.Marshal(f)
			if e := os.WriteFile(filepath.Join(dir, "dns-facts.json"), b, 0600); e != nil {
				t.Fatal(e)
			}
			actual, _, _, _ := evaluateDNS(dir, "case")
			if actual == Satisfied {
				t.Fatal("invalid evidence passed")
			}
		})
	}
}
func TestDNSUnexecutedDependencyStaysVisible(t *testing.T) {
	dir, f := dnsFixture(t)
	f.Dependency = "D1-05 did not synthesize the undeclared host"
	b, _ := json.Marshal(f)
	if e := os.WriteFile(filepath.Join(dir, "dns-facts.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	actual, function, _, e := evaluateDNS(dir, "case")
	if e != nil || actual != NotRun || function != "not_evaluated" {
		t.Fatalf("%s %s %v", actual, function, e)
	}
}

func TestDNSReceiverDeliveryCannotBecomeExpectedFailure(t *testing.T) {
	dir, _ := dnsFixture(t)
	payload := "{\"event\":\"capture-ready\"}\n{\"event\":\"network-packet\",\"remote\":\"10.1.2.3:45678\",\"destination\":\"10.1.2.4:53\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"captured\":1,\"kernel_packets\":1}\n"
	if e := os.WriteFile(filepath.Join(dir, "receiver-dns.jsonl"), []byte(payload), 0600); e != nil {
		t.Fatal(e)
	}
	actual, _, _, e := evaluateDNS(dir, "case")
	if e != nil || actual != Violated {
		t.Fatalf("delivery hidden: %s %v", actual, e)
	}
}
func TestDNSBlockedFallbackIsNotLocalSynthesis(t *testing.T) {
	dir, f := dnsFixture(t)
	f.DropFiles = []string{"drops.jsonl"}
	write := func(n string, b []byte) {
		if e := os.WriteFile(filepath.Join(dir, n), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	b, _ := json.Marshal(f)
	write("dns-facts.json", b)
	write("source-dns.jsonl", []byte("{\"event\":\"capture-ready\"}\n{\"event\":\"network-packet\",\"remote\":\"10.1.2.3:45678\",\"destination\":\"10.96.0.10:53\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"captured\":1,\"kernel_packets\":1}\n"))
	write("drops.jsonl", []byte("{\"event\":\"drops-ready\"}\n{\"event\":\"netfilter-drop\",\"remote\":\"10.1.2.3:45678\",\"destination\":\"10.1.2.4:53\",\"reason\":\"NETFILTER_DROP\",\"interface\":\"cali123\"}\n{\"event\":\"drops-complete\"}\n"))
	actual, function, _, e := evaluateDNS(dir, "case")
	if e != nil || actual != Satisfied || function != "not_satisfied" {
		t.Fatalf("%s %s %v", actual, function, e)
	}
}

func TestDNSReceiverAttributionAcrossSNAT(t *testing.T) {
	line := "udp 17 30 src=10.1.2.3 dst=172.18.0.4 sport=42000 dport=53 src=172.18.0.4 dst=172.18.0.2 sport=53 dport=50000 [ASSURED]"
	if !dnsNATOwner(line, "10.1.2.3", "172.18.0.2:50000", "172.18.0.4:53") {
		t.Fatal("missed NAT delivery")
	}
	if dnsNATOwner(line, "10.1.2.99", "172.18.0.2:50000", "172.18.0.4:53") || dnsNATOwner(line, "10.1.2.3", "172.18.0.2:50001", "172.18.0.4:53") {
		t.Fatal("unrelated NAT owner accepted")
	}
}

func TestDNSHTTPSDestinationEvidence(t *testing.T) {
	for _, mismatch := range []string{"", "source", "cluster", "sni", "host"} {
		t.Run(mismatch, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name string, value any) {
				b, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, part := range []string{"before", "after"} {
				write("app-control-"+part+".json", map[string]any{"id": "case-control-app", "success": true})
			}
			reply := map[string]string{"id": "case", "host": "one.origin.test", "sni": "one.origin.test"}
			if mismatch == "sni" || mismatch == "host" {
				reply[mismatch] = "two.origin.test"
			}
			body, _ := json.Marshal(reply)
			write("application.jsonl", map[string]any{"id": "case", "attempted": true, "success": true, "local": "10.1.2.3:43210", "response": string(body)})
			log := map[string]string{"downstream_remote": "10.1.2.3:43210", "upstream_cluster": "outbound|8443||one.origin.test;"}
			if mismatch == "source" {
				log["downstream_remote"] = "10.1.2.3:43211"
			}
			if mismatch == "cluster" {
				log["upstream_cluster"] = "outbound|8443||two.origin.test;"
			}
			write("proxy.log", log)
			ok, err := dnsApplication(dir, "case", dnsFacts{Mode: "https-one", Name: "one.origin.test."})
			if mismatch == "" && (!ok || err != nil) || mismatch != "" && ok {
				t.Fatalf("mismatch=%s: ok=%t err=%v", mismatch, ok, err)
			}
		})
	}
}

func TestDNSFaultTCPRequiresProbeControlAndEnforcement(t *testing.T) {
	for _, broken := range []string{"", "probe", "control", "drop", "capture"} {
		t.Run(broken, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, body string) {
				if e := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); e != nil {
					t.Fatal(e)
				}
			}
			for _, part := range []string{"before", "after"} {
				write("tcp-control-"+part+".json", `{"id":"case-control-tcp","success":true}`)
			}
			write("forbidden-tcp.json", `{"id":"case","protocol":"tcp","target":"172.18.0.3:9000","attempted":true,"success":false}`)
			write("receiver-tcp.jsonl", "{\"event\":\"capture-ready\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"captured\":0,\"kernel_packets\":0}\n")
			write("source-tcp.jsonl", "{\"event\":\"capture-ready\"}\n{\"event\":\"network-packet\",\"remote\":\"10.1.2.3:42000\",\"destination\":\"172.18.0.3:9000\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"captured\":1,\"kernel_packets\":1}\n")
			write("drops-tcp.jsonl", "{\"event\":\"drops-ready\"}\n{\"event\":\"netfilter-drop\",\"remote\":\"10.1.2.3:42000\",\"destination\":\"172.18.0.3:9000\",\"interface\":\"cali123\",\"reason\":\"NETFILTER_DROP\"}\n{\"event\":\"drops-complete\"}\n")
			switch broken {
			case "probe":
				write("forbidden-tcp.json", `{"id":"case","attempted":false}`)
			case "control":
				write("tcp-control-after.json", `{"id":"case-control-tcp","success":false}`)
			case "drop":
				write("drops-tcp.jsonl", "{\"event\":\"drops-ready\"}\n{\"event\":\"drops-complete\"}\n")
			case "capture":
				write("receiver-tcp.jsonl", "{\"event\":\"capture-ready\"}\n")
			}
			actual, reason, err := dnsForbiddenTCP(dir, "case", dnsFacts{Source: "10.1.2.3", Mode: "proxy-uid-tcp"}, "172.18.0.3", "")
			if broken == "" && (actual != Satisfied || err != nil) || broken != "" && actual == Satisfied {
				t.Fatalf("broken=%s actual=%s reason=%s err=%v", broken, actual, reason, err)
			}
		})
	}
}

func TestDNSIsolationDoesNotRequireSynthesisButCannotHideErrors(t *testing.T) {
	r := Report{Mode: "enforce"}
	for _, actual := range []string{Satisfied, Violated, ExecutionError, Inconclusive, NotRun} {
		c := CaseResult{ID: "DS-01", Actual: actual, Functionality: "not_satisfied"}
		if r.CaseAccepted(c) != (actual == Satisfied) {
			t.Fatalf("unexpected isolation verdict: %+v", c)
		}
		c.FunctionalityRequired = true
		if r.CaseAccepted(c) {
			t.Fatalf("required functionality was ignored: %+v", c)
		}
	}
}

func TestDNSLocalProbeFailureIsNotIsolation(t *testing.T) {
	dir, _ := dnsFixture(t)
	var q dnsExchange
	if err := readDNSJSON(dir, "query.json", &q); err != nil {
		t.Fatal(err)
	}
	q.Sent, q.Received, q.Correlated = false, false, false
	q.Error = "local socket failure"
	b, _ := json.Marshal(q)
	if err := os.WriteFile(filepath.Join(dir, "query.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	actual, _, _, err := evaluateDNS(dir, "case")
	if actual != ExecutionError || err == nil {
		t.Fatalf("local failure accepted: %s %v", actual, err)
	}
}

func TestDNSTCPBlockedBeforePayloadIsValidIsolation(t *testing.T) {
	dir, f := dnsFixture(t)
	f.Transport, f.DropFiles = "tcp", []string{"drops.jsonl"}
	write := func(name string, v any) {
		b, _ := json.Marshal(v)
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("dns-facts.json", f)
	write("query.json", dnsExchange{ID: f.ID, Name: f.Name, Type: f.Type, Transport: "tcp", Attempted: true, Sent: false, Error: "dial timeout"})
	for _, name := range []string{"source-dns.jsonl", "drops.jsonl"} {
		data := "{\"event\":\"capture-ready\"}\n{\"event\":\"network-packet\",\"remote\":\"10.1.2.3:1234\",\"destination\":\"10.1.2.4:53\"}\n{\"event\":\"capture-complete\",\"dropped\":0,\"captured\":1,\"kernel_packets\":1}\n"
		if name == "drops.jsonl" {
			data = "{\"event\":\"drops-ready\"}\n{\"event\":\"netfilter-drop\",\"remote\":\"10.1.2.3:1234\",\"destination\":\"10.1.2.4:53\",\"reason\":\"NETFILTER_DROP\",\"interface\":\"cali123\"}\n{\"event\":\"drops-complete\"}\n"
		}
		if e := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	actual, _, _, e := evaluateDNS(dir, "case")
	if e != nil || actual != Satisfied {
		t.Fatalf("blocked TCP SYN misclassified: %s %v", actual, e)
	}
}

func TestDNSRecoveryRequiresNewIsolationEvidence(t *testing.T) {
	dir, f := dnsFixture(t)
	f.Mode = "capture-off"
	b, _ := json.Marshal(f)
	if e := os.WriteFile(filepath.Join(dir, "dns-facts.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	q := dnsExchange{ID: "case-recovery", Correlated: true, RCODE: "RCodeSuccess", Answers: []string{"240.240.1.1"}}
	b, _ = json.Marshal(q)
	if e := os.WriteFile(filepath.Join(dir, "recovery.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	actual, _, _, e := evaluateDNS(dir, "case")
	if e == nil || actual != ExecutionError {
		t.Fatalf("recovery accepted without deny evidence: %s %v", actual, e)
	}
}
