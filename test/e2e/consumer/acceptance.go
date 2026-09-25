package consumer

import (
	"encoding/json"
	"io"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RenderAcceptance is the policy-only static consumer for independent bindings.
func RenderAcceptance(out io.Writer, image string) error {
	var objects []any
	objects = append(objects, &core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "networking-enrollment", Labels: map[string]string{"istio-injection": "disabled"}}})
	for _, binding := range []string{"a", "b"} {
		app := "httpbin"
		if binding == "b" {
			app = "other"
		}
		n := enrollment.Network{Namespace: "networking-enrollment", Binding: binding, Forward: []enrollment.TCPDestination{{Peer: enrollment.Peer{Namespace: "networking-np", PodLabels: map[string]string{"app": app}}, Ports: []int32{8080}}}}
		p, err := enrollment.ExpandPolicy(n)
		if err != nil {
			return err
		}
		objects = append(objects, &network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: binding, Namespace: n.Namespace}, Spec: p.Spec})
		objects = append(objects, &core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: binding, Namespace: n.Namespace, Labels: p.Labels}, Spec: core.PodSpec{AutomountServiceAccountToken: new(false), Containers: []core.Container{{Name: "probe", Image: image, ImagePullPolicy: core.PullNever, Args: []string{"idle"}, SecurityContext: &core.SecurityContext{RunAsUser: new(int64(10000)), RunAsGroup: new(int64(10000)), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}})
	}
	return json.NewEncoder(out).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "items": objects})
}

func RenderResolverPolicy(out io.Writer, namespace, controlIP, resolver string) error {
	n, name, err := Network(namespace, controlIP)
	if err != nil {
		return err
	}
	if resolver != "" {
		n.DNS = []enrollment.Peer{{IPv4: resolver}}
	}
	p, err := enrollment.ExpandPolicy(n)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(&network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: p.Spec})
}
