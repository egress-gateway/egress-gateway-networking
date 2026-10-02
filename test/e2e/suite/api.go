package suite

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	network "k8s.io/api/networking/v1"
)

func evaluateAPI(dir, id, contract string, expected egressInputs) (string, string, error) {
	var f struct{ ID, Phase, Target, Address, Endpoint, Source, Interface string }
	if err := readEvidence(dir, "api.json", &f); err != nil {
		return "", "", err
	}
	if f.ID != id || f.Phase != expected.Phase || f.Target != expected.Target || expected.Protocol != "tcp" || contract != "api-endpoint" || !slices.Contains([]string{"deny", "allow", "wrong-port", "revoke"}, f.Phase) {
		return ExecutionError, "API case identity mismatch", nil
	}
	endpoint, err := netip.ParseAddrPort(f.Endpoint)
	if err != nil || !endpoint.Addr().Is4() || endpoint.Port() == 0 {
		return ExecutionError, "invalid API endpoint", nil
	}
	var service core.Service
	var endpoints discovery.EndpointSliceList
	if err := readEvidence(dir, "api-service.json", &service); err != nil {
		return "", "", err
	}
	if err := readEvidence(dir, "api-endpoints.json", &endpoints); err != nil {
		return "", "", err
	}
	if service.Name != "kubernetes" || service.Namespace != "default" || len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Protocol != core.ProtocolTCP {
		return ExecutionError, "invalid API Service association", nil
	}
	associated := false
	for _, slice := range endpoints.Items {
		if slice.Namespace != "default" || slice.Labels["kubernetes.io/service-name"] != "kubernetes" {
			continue
		}
		portMatch := false
		for _, p := range slice.Ports {
			portMatch = portMatch || p.Protocol != nil && *p.Protocol == core.ProtocolTCP && p.Port != nil && *p.Port == int32(endpoint.Port())
		}
		for _, e := range slice.Endpoints {
			associated = associated || portMatch && (e.Conditions.Ready == nil || *e.Conditions.Ready) && slices.Contains(e.Addresses, endpoint.Addr().String())
		}
	}
	address := f.Endpoint
	if f.Target == "api-service" {
		address = service.Spec.ClusterIP + ":" + strconv.Itoa(int(service.Spec.Ports[0].Port))
	}
	if !associated || f.Address != address {
		return ExecutionError, "API endpoint/Service translation not associated", nil
	}
	n := enrollment.Network{Namespace: "networking-np", Binding: "np"}
	if f.Phase == "allow" || f.Phase == "wrong-port" {
		port := int32(endpoint.Port())
		if f.Phase == "wrong-port" {
			port++
		}
		n.Forward = []enrollment.TCPDestination{{Peer: enrollment.Peer{IPv4: endpoint.Addr().String()}, Ports: []int32{port}}}
	}
	want, err := enrollment.ExpandPolicy(n)
	if err != nil {
		return "", "", err
	}
	var actual network.NetworkPolicy
	if err := readEvidence(dir, "effective-policy.json", &actual); err != nil {
		return "", "", err
	}
	if actual.Name != "api-case" || actual.Namespace != n.Namespace || !reflect.DeepEqual(actual.Spec, want.Spec) {
		return ExecutionError, "API allowance differs from the exact selected policy", nil
	}
	for _, part := range []string{"before", "after"} {
		ps, err := records(filepath.Join(dir, "control-"+part+".jsonl"))
		if err != nil {
			return "", "", err
		}
		if len(ps) != 1 || ps[0].ID != id+"-control-"+part || !ps[0].Attempted || !ps[0].Success || ps[0].Target != f.Address {
			return ExecutionError, "API receiver control failed " + part, nil
		}
	}
	if f.Phase != "deny" {
		ps, err := records(filepath.Join(dir, "pre-change.jsonl"))
		if err != nil {
			return "", "", err
		}
		if len(ps) != 1 || ps[0].ID != id+"-settle" || ps[0].UID != 10000 || !ps[0].Success || ps[0].Target != f.Address {
			return ExecutionError, "API prior exact allowance not proven", nil
		}
	}
	ps, err := records(filepath.Join(dir, "probe.jsonl"))
	if err != nil {
		return "", "", err
	}
	if len(ps) != 1 || ps[0].ID != id || ps[0].UID != 10000 || !ps[0].Attempted || ps[0].Protocol != "tcp" || ps[0].Target != f.Address || ps[0].Started.IsZero() || ps[0].Finished.Before(ps[0].Started) || peerIP(ps[0].Local) != f.Source {
		return ExecutionError, "API application attempt not associated", nil
	}
	p := ps[0]
	if f.Phase == "allow" {
		if !p.Success {
			return Violated, "exact API endpoint allowance did not permit TCP", nil
		}
		return Satisfied, "exact selected API IPv4/TCP endpoint reachable; Service association verified; authentication and RBAC not inferred", nil
	}
	if p.Success || p.Connected {
		return Violated, "API TCP connected without the exact endpoint allowance", nil
	}
	drops, err := records(filepath.Join(dir, "drops.jsonl"))
	if err != nil {
		return "", "", err
	}
	ready, complete, matched := false, false, false
	for _, d := range drops {
		ready = ready || d.Event == "drops-ready" && d.Target == f.Endpoint
		complete = complete || d.Event == "drops-complete"
		matched = matched || d.Event == "netfilter-drop" && d.Reason == "NETFILTER_DROP" && d.Remote == p.Local && d.Destination == f.Endpoint && d.Interface == f.Interface && !d.Time.Before(p.Started) && !d.Time.After(p.Finished)
	}
	if !ready || !complete || !matched {
		return Inconclusive, "API failure lacks kernel drop at the actual post-translation endpoint during this attempt", nil
	}
	return Satisfied, "new API TCP attempt denied by workload policy with exact source/time/endpoint drop and healthy controls", nil
}
