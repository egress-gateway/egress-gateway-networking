package suite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type dnsDiscovery struct {
	Cluster, External, ExternalContainer, Control, ControlNamespace, Service, Namespace, Pod string
	Endpoints                                                                                []struct{ Name, IP, PID string }
}
type dnsRunner struct {
	s                                                                                      *Suite
	id, dir, caseID, mode, transport, qtype, question, ns, pod, source, sourcePID, started string
	discovery                                                                              dnsDiscovery
	observers                                                                              []*dnsObserver
	observerContext                                                                        context.Context
	cancelObservers                                                                        context.CancelFunc
	facts                                                                                  dnsFacts
	created, suspendIntent, restartIntent, staleIntent                                     bool
	phases                                                                                 []PhaseTiming
}
type PhaseTiming struct {
	Name    string  `json:"name"`
	Seconds float64 `json:"seconds"`
	Error   string  `json:"error,omitempty"`
}

func (r *dnsRunner) stage(name string, op func() error) (err error) {
	start := time.Now()
	defer func() {
		p := PhaseTiming{Name: name, Seconds: time.Since(start).Seconds()}
		if err != nil {
			p.Error = err.Error()
		}
		r.phases = append(r.phases, p)
		if r.s.Report != nil && r.caseID != "" {
			err = errors.Join(err, r.s.Report.Update(func(report *Report) {
				for i := range report.Cases {
					if report.Cases[i].ID == r.caseID {
						report.Cases[i].Phases = append([]PhaseTiming{}, r.phases...)
					}
				}
			}))
		}
		err = errors.Join(err, r.write("dns-phases.json", r.phases))
	}()
	return op()
}
func (s *Suite) runDNS(ctx context.Context, dir, id, caseID, mode, transport, qtype string) error {
	r := &dnsRunner{s: s, dir: dir, id: id, caseID: caseID, mode: mode, transport: transport, qtype: qtype}
	return r.run(ctx, true)
}
func (r *dnsRunner) operation(ctx context.Context, phase, target, client string) error {
	return r.s.Execute(ctx, "test/e2e/scripts/dns-operation.sh", "--state-dir", r.s.State, "--artifacts", r.dir, "--test-id", r.id, "--phase", phase, "--target", target, "--client", client, "--dns-lane", r.s.dnsLane)
}
func (r *dnsRunner) run(ctx context.Context, recovery bool) (result error) {
	if err := os.MkdirAll(r.dir, 0700); err != nil {
		return err
	}
	r.observerContext, r.cancelObservers = context.WithCancel(context.WithoutCancel(ctx))
	defer r.cancelObservers()
	defer func() {
		err := r.stage("cleanup", func() error { return dnsCleanup(ctx, 10*time.Second, r.stopObservers, r.restore) })
		result = errors.Join(result, err)
		if result != nil {
			result = errors.Join(result, os.WriteFile(filepath.Join(r.s.State, "fault-active"), []byte(r.id+"\n"), 0600))
		}
	}()
	if err := r.stage("prepare", func() error {
		if err := r.operation(ctx, "discover", r.mode, r.qtype); err != nil {
			return err
		}
		if err := readDNSJSON(r.dir, "discovery.json", &r.discovery); err != nil {
			return err
		}
		if len(r.discovery.Endpoints) == 0 {
			return errors.New("no DNS receivers discovered")
		}
		r.ns, r.pod = r.discovery.Namespace, r.discovery.Pod
		r.question = r.id + ".unregistered.test"
		switch r.mode {
		case "declared", "edns", "record", "stale-vip":
			r.question = r.id + ".origin.test"
		case "wildcard":
			r.question = r.id + ".wild.origin.test"
		case "other-suffix":
			r.question = r.id + ".unregistered.invalid"
		case "search":
			r.question = r.id + ".external.test." + r.s.dnsNamespace() + ".svc.cluster.local"
		case "http-one", "https-one", "restart", "recreate", "bootstrap-mapped":
			r.question = "one.origin.test"
		case "http-two", "https-two":
			r.question = "two.origin.test"
		case "raw-tcp":
			r.question = "tcp.origin.test"
		}
		types := map[string]uint16{"A": 1, "AAAA": 28, "TXT": 16, "SRV": 33, "MX": 15, "PTR": 12, "NULL": 10, "ANY": 255}
		r.facts = dnsFacts{ID: r.id, Mode: r.mode, Name: r.question + ".", Transport: r.transport, Type: types[r.qtype], FaultVerified: true}
		return nil
	}); err != nil {
		return err
	}
	if err := r.stage("health-before", func() error { return r.health(ctx, "before") }); err != nil {
		return err
	}
	if r.mode == "restart" || r.mode == "recreate" {
		if err := r.query(ctx, "cached.json", "one.origin.test", r.id+"-cache", "udp", "A", "", false, 7*time.Second); err != nil {
			return err
		}
		if err := r.validVIP("cached.json"); err != nil {
			return err
		}
	}
	if err := r.stage("receiver-observers-ready", func() error {
		var obs []*dnsObserver
		for i, e := range r.discovery.Endpoints {
			name := fmt.Sprintf("receiver-dns-%d", i)
			drop := fmt.Sprintf("drops-dns-%d", i)
			obs = append(obs, r.observer(name, "capture", e.PID, 53), r.observer(drop, "drops", e.IP+":53", 53))
			r.facts.Captures = append(r.facts.Captures, name+".jsonl")
			r.facts.DropFiles = append(r.facts.DropFiles, drop+".jsonl")
		}
		obs = append(obs, r.observer("receiver-external", "external", "", 53), r.observer("drops-external", "drops", r.discovery.External+":53", 53))
		r.facts.Captures = append(r.facts.Captures, "receiver-external.jsonl")
		r.facts.DropFiles = append(r.facts.DropFiles, "drops-external.jsonl")
		if r.forbiddenTCP() {
			obs = append(obs, r.observer("receiver-tcp", "external", "", 9000), r.observer("drops-tcp", "drops", r.discovery.External+":9000", 9000))
			r.facts.DropFiles = append(r.facts.DropFiles, "drops-tcp.jsonl")
		}
		return r.startObservers(ctx, obs...)
	}); err != nil {
		return err
	}
	if err := r.stage("fixture-ready", func() error { return r.prepareSource(ctx) }); err != nil {
		return err
	}
	if err := r.stage("source-observers-ready", func() error {
		obs := []*dnsObserver{r.observer("source-dns", "capture", r.sourcePID, 53)}
		r.facts.Captures = append(r.facts.Captures, "source-dns.jsonl")
		if r.forbiddenTCP() {
			obs = append(obs, r.observer("source-tcp", "capture", r.sourcePID, 9000))
		}
		if err := r.startObservers(ctx, obs...); err != nil {
			return err
		}
		b, err := r.command(ctx, "docker", "exec", r.discovery.Cluster+"-control-plane", "date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ")
		r.started = strings.TrimSpace(string(b))
		return err
	}); err != nil {
		return err
	}
	if err := r.stage("probe", func() error { return r.probe(ctx) }); err != nil {
		return err
	}
	if err := r.stage("observation-complete", func() error {
		// conntrack may exit nonzero for an empty table; attribution still validates its contents.
		_ = r.saveCommand(ctx, "conntrack.txt", "docker", "exec", r.discovery.Cluster+"-control-plane", "conntrack", "-L", "--orig-src", r.source)
		return r.stopObservers(ctx)
	}); err != nil {
		return err
	}
	if err := r.stage("health-after", func() error { return r.health(ctx, "after") }); err != nil {
		return err
	}
	if err := r.stage("collect", func() error {
		if err := r.saveK(ctx, "pod-after.json", "-n", r.ns, "get", "pod", r.pod, "-o", "json"); err != nil {
			return err
		}
		if err := r.saveK(ctx, "receiver.log", "-n", r.s.dnsNamespace(), "logs", "receiver", "--since-time="+r.started); err != nil {
			return err
		}
		b, err := r.k(ctx, "-n", r.s.dnsNamespace(), "get", "pod", "receiver", "-o", "json")
		if err != nil {
			return err
		}
		var p dnsPod
		if err = json.Unmarshal(b, &p); err != nil {
			return err
		}
		if err = r.write("application-receiver.json", map[string]string{"uid": p.Metadata.UID, "ip": p.Status.PodIP}); err != nil {
			return err
		}
		return r.operation(ctx, "snapshot", "", "")
	}); err != nil {
		return err
	}
	if err := r.stage("recovery", func() error {
		if err := r.restore(ctx); err != nil {
			return err
		}
		if !recovery || !dnsNeedsRecovery(r.mode) {
			return nil
		}
		if err := r.queryFrom(ctx, r.s.dnsNamespace(), "client", "recovery.json", "one.origin.test", r.id+"-recovery", "udp", "A", "", false, 7*time.Second); err != nil {
			return err
		}
		if err := r.validVIP("recovery.json"); err != nil {
			return err
		}
		child := &dnsRunner{s: r.s, dir: filepath.Join(r.dir, "recovery-isolation"), id: r.id + "-recovery-isolation", mode: "unregistered", transport: r.transport, qtype: "A"}
		if err := child.run(ctx, false); err != nil {
			return err
		}
		actual, _, reason, err := evaluateDNS(child.dir, child.id)
		if err != nil || actual != Satisfied {
			return fmt.Errorf("recovery isolation: %s: %w", reason, errors.Join(err, errors.New("recovery not satisfied")))
		}
		return nil
	}); err != nil {
		return err
	}
	r.facts.Restored = true
	return r.write("dns-facts.json", r.facts)
}
func (r *dnsRunner) forbiddenTCP() bool {
	return slices.Contains([]string{"capture-off-tcp", "proxy-uid-tcp", "sidecar-stopped-tcp"}, r.mode)
}
func (r *dnsRunner) app() bool {
	return strings.HasPrefix(r.mode, "http-") || strings.HasPrefix(r.mode, "https-") || slices.Contains([]string{"raw-tcp", "stale-vip", "restart", "recreate"}, r.mode)
}
func (r *dnsRunner) health(ctx context.Context, part string) error {
	var ops []func(context.Context) error
	for i, e := range r.discovery.Endpoints {
		file := fmt.Sprintf("control-%s-%d.json", part, i)
		r.facts.Controls = append(r.facts.Controls, file)
		ops = append(ops, func(ctx context.Context) error {
			return r.queryFrom(ctx, r.discovery.ControlNamespace, r.discovery.Control, file, "kubernetes.default.svc.cluster.local", r.id+"-control", r.transport, "A", e.IP+":53", false, 3*time.Second)
		})
	}
	file := "control-" + part + "-external.json"
	r.facts.Controls = append(r.facts.Controls, file)
	ops = append(ops, func(ctx context.Context) error {
		return r.queryFrom(ctx, r.discovery.ControlNamespace, r.discovery.Control, file, r.id+".control.test", r.id+"-control", r.transport, "A", r.discovery.External+":53", false, 3*time.Second)
	})
	if r.app() {
		ops = append(ops, func(ctx context.Context) error {
			var a struct{ Receiver string }
			if err := readDNSJSON(r.s.State, r.s.dnsState()+"/addresses.json", &a); err != nil {
				return err
			}
			proto, port := r.appProtocol()
			return r.saveK(ctx, "app-control-"+part+".json", "-n", r.discovery.ControlNamespace, "exec", r.discovery.Control, "-c", "probe", "--", "/probe", "request", "--protocol", proto, "--target", a.Receiver+":"+port, "--server-name", "one.origin.test", "--id", r.id+"-control-app", "--timeout", "3s")
		})
	}
	if r.forbiddenTCP() {
		ops = append(ops, func(ctx context.Context) error {
			return r.saveK(ctx, "tcp-control-"+part+".json", "-n", r.discovery.ControlNamespace, "exec", r.discovery.Control, "-c", "probe", "--", "/probe", "request", "--protocol", "tcp", "--target", r.discovery.External+":9000", "--id", r.id+"-control-tcp", "--timeout", "3s")
		})
	}
	return dnsParallel(ctx, ops...)
}
func (r *dnsRunner) query(ctx context.Context, file, name, id, transport, qtype, target string, edns bool, timeout time.Duration) error {
	return r.queryFrom(ctx, r.ns, r.pod, file, name, id, transport, qtype, target, edns, timeout)
}
func (r *dnsRunner) queryFrom(ctx context.Context, ns, pod, file, name, id, transport, qtype, target string, edns bool, timeout time.Duration) error {
	args := []string{"-n", ns, "exec", pod, "-c", "probe", "--", "/probe", "dns", "--query", name, "--id", id, "--transport", transport, "--qtype", qtype, "--timeout", timeout.String()}
	if target != "" {
		args = append(args, "--target", target)
	}
	if edns {
		args = append(args, "--edns")
	}
	return r.saveK(ctx, file, args...)
}
func (r *dnsRunner) validVIP(file string) error {
	var q dnsExchange
	if err := readDNSJSON(r.dir, file, &q); err != nil {
		return err
	}
	if !q.Sent || !q.Correlated || q.RCODE != "RCodeSuccess" || len(q.Answers) == 0 {
		return errors.New("local resolution failed")
	}
	for _, a := range q.Answers {
		if !strings.HasPrefix(a, "240.240.") {
			return errors.New("local resolution returned non-synthetic answer")
		}
	}
	return nil
}

type dnsPod struct {
	Metadata struct{ UID, Name string }
	Status   struct {
		PodIP                 string
		Conditions            []struct{ Type, Status string }
		ContainerStatuses     []dnsContainer
		InitContainerStatuses []dnsContainer
	}
}
type dnsContainer struct {
	Name, ContainerID string
	Ready             bool
}

func (r *dnsRunner) ready(ctx context.Context, ns, pod, old string) error {
	return dnsPoll(ctx, 90*time.Second, func(ctx context.Context) (bool, error) {
		b, err := r.k(ctx, "-n", ns, "get", "pod", pod, "-o", "json")
		if err != nil {
			return false, err
		}
		var p dnsPod
		if err = json.Unmarshal(b, &p); err != nil {
			return false, err
		}
		ready := false
		for _, c := range p.Status.Conditions {
			ready = ready || c.Type == "Ready" && c.Status == "True"
		}
		if old != "" {
			changed := false
			for _, c := range append(p.Status.ContainerStatuses, p.Status.InitContainerStatuses...) {
				changed = changed || c.Name == "istio-proxy" && c.ContainerID != old && c.Ready
			}
			ready = ready && changed
		}
		return ready, nil
	})
}
func (r *dnsRunner) prepareSource(ctx context.Context) error {
	fault := strings.TrimSuffix(r.mode, "-tcp")
	if slices.Contains([]string{"bootstrap-mapped", "capture-off", "capture-excluded", "proxy-uid", "nameserver", "recreate"}, fault) {
		r.pod = "dns-" + r.id
		r.created = true
		if err := r.operation(ctx, "create", fault, ""); err != nil {
			return err
		}
		if err := r.ready(ctx, r.ns, r.pod, ""); err != nil {
			return err
		}
	}
	if err := r.operation(ctx, "source", r.ns, r.pod); err != nil {
		return err
	}
	var pod struct {
		IP          string
		Annotations map[string]string
		Security    []struct {
			Name            string
			SecurityContext struct{ RunAsUser int }
		}
	}
	if err := readDNSJSON(r.dir, "pod-before.json", &pod); err != nil {
		return err
	}
	r.source = pod.IP
	r.facts.Source = r.source
	pid, err := os.ReadFile(filepath.Join(r.dir, "source-pid"))
	if err != nil {
		return err
	}
	r.sourcePID = strings.TrimSpace(string(pid))
	redirects, err := os.ReadFile(filepath.Join(r.dir, "redirect.txt"))
	if err != nil {
		return err
	}
	switch fault {
	case "capture-off":
		for line := range strings.SplitSeq(string(redirects), "\n") {
			if strings.Contains(line, "--dport 53") && strings.Contains(line, "15053") {
				return errors.New("DNS capture disable did not take effect")
			}
		}
	case "capture-excluded":
		if pod.Annotations["traffic.sidecar.istio.io/excludeOutboundPorts"] != "53" || !strings.Contains(string(redirects), "--dport 53 -j RETURN") {
			return errors.New("DNS exclusion did not take effect")
		}
	case "proxy-uid":
		verified := false
		for _, c := range pod.Security {
			verified = verified || c.Name == "probe" && c.SecurityContext.RunAsUser == 1337
		}
		if !verified {
			return errors.New("UID exclusion did not take effect")
		}
	case "sidecar-stopped":
		r.suspendIntent = true
		if err := r.operation(ctx, "suspend", r.ns, r.pod); err != nil {
			return err
		}
	}
	if slices.Contains([]string{"declared", "edns", "record"}, r.mode) {
		if err := r.configureName(ctx, "dns-origin", []string{"one.origin.test", "two.origin.test", r.question}); err != nil {
			return err
		}
		if err := r.waitCluster(ctx, r.question, true); err != nil {
			return err
		}
	}
	endpoints := make([]string, 0, len(r.discovery.Endpoints))
	for _, e := range r.discovery.Endpoints {
		endpoints = append(endpoints, e.IP)
	}
	return r.write("dns-tuples.json", map[string]any{"source": r.source, "service": r.discovery.Service, "endpoints": endpoints, "external": r.discovery.External})
}
func (r *dnsRunner) configureName(ctx context.Context, name string, hosts []string) error {
	b, err := r.k(ctx, "-n", r.s.dnsNamespace(), "get", "serviceentry", "dns-origin", "-o", "json")
	if err != nil {
		return err
	}
	var v map[string]any
	if err = json.Unmarshal(b, &v); err != nil {
		return err
	}
	delete(v, "status")
	if name != "dns-origin" {
		v["metadata"] = map[string]any{"name": name, "namespace": r.s.dnsNamespace()}
	}
	spec, ok := v["spec"].(map[string]any)
	if !ok {
		return errors.New("missing ServiceEntry spec")
	}
	spec["hosts"] = hosts
	return r.apply(ctx, v)
}
func (r *dnsRunner) waitCluster(ctx context.Context, name string, present bool) error {
	return dnsPoll(ctx, 20*time.Second, func(ctx context.Context) (bool, error) {
		b, err := r.k(ctx, "-n", r.ns, "exec", r.pod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "clusters")
		if err != nil {
			return false, err
		}
		return strings.Contains(string(b), "||"+name+"::") == present, nil
	})
}
func (r *dnsRunner) appProtocol() (string, string) {
	if strings.HasPrefix(r.mode, "https-") {
		return "https", "8443"
	}
	if r.mode == "raw-tcp" {
		return "tcp", "9000"
	}
	return "http", "8080"
}
func (r *dnsRunner) application(ctx context.Context, file, proto, target, host string, timeout time.Duration) error {
	err := r.saveK(ctx, file, "-n", r.ns, "exec", r.pod, "-c", "probe", "--", "/probe", "request", "--protocol", proto, "--target", target, "--host", host, "--server-name", host, "--id", r.id, "--timeout", timeout.String())
	// Negative requests may return nonzero, but must leave a parseable attempt.
	ps, readErr := records(filepath.Join(r.dir, file))
	if readErr != nil || len(ps) == 0 {
		return errors.Join(err, readErr, errors.New("missing application probe record"))
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if r.forbiddenTCP() && !ps[0].Success {
		return nil
	}
	return dnsPoll(ctx, 10*time.Second, func(ctx context.Context) (bool, error) {
		if err := r.saveK(ctx, "proxy.log", "-n", r.ns, "logs", r.pod, "-c", "istio-proxy", "--since-time="+r.started); err != nil {
			return false, err
		}
		b, err := os.ReadFile(filepath.Join(r.dir, "proxy.log"))
		if err != nil {
			return false, err
		}
		return strings.Contains(string(b), r.id) || (ps[0].Local != "" && strings.Contains(string(b), ps[0].Local)), nil
	})
}
func (r *dnsRunner) probe(ctx context.Context) error {
	r.facts.Attempted = true
	switch {
	case r.forbiddenTCP():
		return r.application(ctx, "forbidden-tcp.json", "tcp", r.discovery.External+":9000", "", 4*time.Second)
	case strings.HasPrefix(r.mode, "http-") || strings.HasPrefix(r.mode, "https-") || r.mode == "raw-tcp":
		proto, port := r.appProtocol()
		return r.application(ctx, "application.jsonl", proto, r.question+":"+port, r.question, 8*time.Second)
	case r.mode == "bootstrap-mapped":
		if err := r.ready(ctx, r.ns, r.pod, ""); err != nil {
			return err
		}
		r.facts.Ready = true
		r.facts.Functional = true
		if err := r.saveK(ctx, "certificates.json", "-n", r.ns, "exec", r.pod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "certs"); err != nil {
			return err
		}
		return r.saveK(ctx, "bootstrap.log", "-n", r.ns, "logs", r.pod, "-c", "istio-proxy", "--tail=100")
	case r.mode == "restart" || r.mode == "recreate":
		if r.mode == "restart" {
			b, err := r.k(ctx, "-n", r.ns, "get", "pod", r.pod, "-o", "json")
			if err != nil {
				return err
			}
			var p dnsPod
			if err = json.Unmarshal(b, &p); err != nil {
				return err
			}
			old := ""
			for _, c := range append(p.Status.ContainerStatuses, p.Status.InitContainerStatuses...) {
				if c.Name == "istio-proxy" {
					old = c.ContainerID
				}
			}
			if !strings.HasPrefix(old, "containerd://") {
				return errors.New("missing sidecar container identity")
			}
			r.restartIntent = true
			if _, err = r.command(ctx, "docker", "exec", r.discovery.Cluster+"-control-plane", "crictl", "stop", strings.TrimPrefix(old, "containerd://")); err != nil {
				return err
			}
			if err = r.ready(ctx, r.ns, r.pod, old); err != nil {
				return err
			}
			r.restartIntent = false
		}
		if err := r.query(ctx, "query.json", r.question, r.id, "udp", "A", "", false, 7*time.Second); err != nil {
			return err
		}
		if err := r.validVIP("query.json"); err != nil {
			return err
		}
		r.facts.Functional = true
		var q dnsExchange
		if err := readDNSJSON(r.dir, "cached.json", &q); err != nil {
			return err
		}
		return r.application(ctx, "application.jsonl", "http", q.Answers[0]+":8080", "one.origin.test", 4*time.Second)
	case r.mode == "stale-vip":
		r.staleIntent = true
		if err := r.configureName(ctx, "dns-stale", []string{r.question}); err != nil {
			return err
		}
		if err := dnsPoll(ctx, 20*time.Second, func(ctx context.Context) (bool, error) {
			err := r.query(ctx, "cached.json", r.question, r.id, "udp", "A", "", false, time.Second)
			return err == nil && r.validVIP("cached.json") == nil, nil
		}); err != nil {
			return err
		}
		var q dnsExchange
		if err := readDNSJSON(r.dir, "cached.json", &q); err != nil {
			return err
		}
		if _, err := r.k(ctx, "-n", r.ns, "delete", "serviceentry", "dns-stale", "--wait=false"); err != nil {
			return err
		}
		r.staleIntent = false
		if err := r.waitCluster(ctx, r.question, false); err != nil {
			return err
		}
		return r.application(ctx, "application.jsonl", "http", q.Answers[0]+":8080", r.question, 4*time.Second)
	default:
		target := ""
		switch r.mode {
		case "service":
			target = r.discovery.Service + ":53"
		case "endpoint":
			target = r.discovery.Endpoints[0].IP + ":53"
		case "external", "egress-external":
			target = r.discovery.External + ":53"
		}
		timeout := 7 * time.Second
		if slices.Contains([]string{"capture-off", "capture-excluded", "proxy-uid", "sidecar-stopped"}, r.mode) {
			timeout = 2 * time.Second
		}
		err := r.query(ctx, "query.json", r.question, r.id, r.transport, r.qtype, target, r.mode == "edns", timeout)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var q dnsExchange
		if e := readDNSJSON(r.dir, "query.json", &q); e != nil {
			return errors.Join(err, e)
		}
		if !q.Attempted {
			return errors.Join(err, errors.New("DNS query was not attempted"))
		}
		return nil
	}
}
func (r *dnsRunner) restore(ctx context.Context) error {
	var errs []error
	if r.suspendIntent {
		b, err := os.ReadFile(filepath.Join(r.dir, "suspended-pids"))
		if errors.Is(err, os.ErrNotExist) {
			r.suspendIntent = false
		} else if err != nil {
			errs = append(errs, err)
		} else {
			args := []string{"exec", r.discovery.Cluster + "-control-plane", "kill", "-CONT"}
			args = append(args, strings.Fields(string(b))...)
			_, err = r.command(ctx, "docker", args...)
			if err == nil {
				err = r.ready(ctx, r.ns, r.pod, "")
			}
			if err == nil {
				r.suspendIntent = false
			}
			errs = append(errs, err)
		}
	}
	if r.restartIntent {
		err := r.ready(ctx, r.ns, r.pod, "")
		if err == nil {
			r.restartIntent = false
		}
		errs = append(errs, err)
	}
	if r.staleIntent {
		_, err := r.k(ctx, "-n", r.s.dnsNamespace(), "delete", "serviceentry", "dns-stale", "--ignore-not-found", "--wait=false")
		if err == nil {
			r.staleIntent = false
		}
		errs = append(errs, err)
	}
	if r.created {
		_, err := r.k(ctx, "-n", r.s.dnsNamespace(), "delete", "pod", r.pod, "--ignore-not-found", "--wait=true", "--timeout=60s")
		if err == nil {
			r.created = false
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
