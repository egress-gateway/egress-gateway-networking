// Package enrollment expands the fixed network contract using caller-resolved
// values. It performs no cluster lookups, resource writes or environment discovery.
package enrollment

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"

	core "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/validation"
)

const BindingLabel = "networking.egress/binding"

// Peer is exactly one IPv4 address or a namespace AND nonempty Pod label set.
// CIDR ranges, selector expressions and namespace-only permissions are not inputs.
type Peer struct {
	IPv4      string            `json:"ipv4,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	PodLabels map[string]string `json:"podLabels,omitempty"`
}

type TCPDestination struct {
	Peer  Peer    `json:"peer"`
	Ports []int32 `json:"ports"`
}

// Istiod describes one resolved control service; its port and TLS verification
// requirements are fixed. IP is supplied by the trusted installation consumer.
type Istiod struct {
	IPv4     string `json:"ipv4"`
	Hostname string `json:"hostname"`
	Peer     Peer   `json:"peer"`
}

// Network can be expanded before a Pod exists. Binding is allocated and protected
// by the caller; using the same binding deliberately selects the same allowance.
type Network struct {
	Namespace string           `json:"namespace"`
	Binding   string           `json:"binding"`
	Forward   []TCPDestination `json:"forward,omitempty"`
	DNS       []Peer           `json:"dns,omitempty"`
	Control   *Istiod          `json:"control,omitempty"`
}

type Policy struct {
	Labels map[string]string
	Spec   network.NetworkPolicySpec
}

// ExpandPolicy leaves policy resource identity, ownership and API writes to the
// caller. An empty exception list still selects and denies Pod egress.
func ExpandPolicy(n Network) (*Policy, error) {
	if len(validation.IsDNS1123Label(n.Namespace)) != 0 {
		return nil, fmt.Errorf("network.namespace: DNS label required")
	}
	if n.Binding == "" || len(validation.IsValidLabelValue(n.Binding)) != 0 {
		return nil, fmt.Errorf("network.binding: nonempty label value required")
	}
	labels := map[string]string{BindingLabel: n.Binding}
	p := &Policy{Labels: labels, Spec: network.NetworkPolicySpec{PodSelector: meta.LabelSelector{MatchLabels: maps.Clone(labels)}, PolicyTypes: []network.PolicyType{network.PolicyTypeEgress}}}
	add := func(peer Peer, ports []int32, protocols []core.Protocol) error {
		v, err := peer.expand()
		if err != nil {
			return err
		}
		if len(ports) == 0 {
			return fmt.Errorf("explicit ports required")
		}
		ports = slices.Clone(ports)
		slices.Sort(ports)
		ports = slices.Compact(ports)
		rule := network.NetworkPolicyEgressRule{To: []network.NetworkPolicyPeer{v}}
		for _, port := range ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("port %d outside 1..65535", port)
			}
			for _, protocol := range protocols {
				rule.Ports = append(rule.Ports, network.NetworkPolicyPort{Protocol: new(protocol), Port: new(intstr.FromInt32(port))})
			}
		}
		p.Spec.Egress = append(p.Spec.Egress, rule)
		return nil
	}
	for i, d := range n.Forward {
		if slices.Contains(d.Ports, 53) {
			return nil, fmt.Errorf("network.forward[%d]: use explicit DNS exceptions for port 53", i)
		}
		if err := add(d.Peer, d.Ports, []core.Protocol{core.ProtocolTCP}); err != nil {
			return nil, fmt.Errorf("network.forward[%d]: %w", i, err)
		}
	}
	for i, d := range n.DNS {
		if err := add(d, []int32{53}, []core.Protocol{core.ProtocolTCP, core.ProtocolUDP}); err != nil {
			return nil, fmt.Errorf("network.dns[%d]: %w", i, err)
		}
	}
	if n.Control != nil {
		if err := validIPv4(n.Control.IPv4); err != nil {
			return nil, fmt.Errorf("network.control.ipv4: %w", err)
		}
		if len(validation.IsDNS1123Subdomain(n.Control.Hostname)) != 0 || n.Control.Hostname == "" {
			return nil, fmt.Errorf("network.control.hostname: DNS hostname required")
		}
		if err := add(n.Control.Peer, []int32{15012}, []core.Protocol{core.ProtocolTCP}); err != nil {
			return nil, fmt.Errorf("network.control.peer: %w", err)
		}
	}
	return p, nil
}

func (p Peer) expand() (network.NetworkPolicyPeer, error) {
	if p.IPv4 != "" {
		if p.Namespace != "" || len(p.PodLabels) != 0 {
			return network.NetworkPolicyPeer{}, fmt.Errorf("choose IPv4 or namespace/Pod peer, not both")
		}
		if err := validIPv4(p.IPv4); err != nil {
			return network.NetworkPolicyPeer{}, err
		}
		return network.NetworkPolicyPeer{IPBlock: &network.IPBlock{CIDR: p.IPv4 + "/32"}}, nil
	}
	if len(validation.IsDNS1123Label(p.Namespace)) != 0 || len(p.PodLabels) == 0 {
		return network.NetworkPolicyPeer{}, fmt.Errorf("namespace AND nonempty Pod labels required")
	}
	for k, v := range p.PodLabels {
		if len(validation.IsQualifiedName(k)) != 0 || v == "" || len(validation.IsValidLabelValue(v)) != 0 {
			return network.NetworkPolicyPeer{}, fmt.Errorf("invalid Pod label %q", k)
		}
	}
	return network.NetworkPolicyPeer{NamespaceSelector: &meta.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": p.Namespace}}, PodSelector: &meta.LabelSelector{MatchLabels: maps.Clone(p.PodLabels)}}, nil
}

func validIPv4(s string) error {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() || !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return fmt.Errorf("exact unicast IPv4 address required: %q", s)
	}
	return nil
}
