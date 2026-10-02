package consumer

import (
	"encoding/json"
	"io"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RenderIntegration is an independent trusted caller, not a Gateway injector.
func RenderIntegration(out io.Writer, image, name, id, target string) error {
	n, _, err := Network("networking-np")
	if err != nil {
		return err
	}
	security := func(uid int64) *core.SecurityContext {
		return &core.SecurityContext{RunAsUser: new(uid), RunAsGroup: new(uid), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}, SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}}
	}
	prep := core.Container{Name: "prepare-network", Image: image, ImagePullPolicy: core.PullNever, SecurityContext: security(0), Command: []string{"/bin/sh", "-ec"}, Args: []string{
		`iptables -w -N NETWORKING_PREP
iptables -w -A NETWORKING_PREP -p tcp --dport 19091 -j REJECT
iptables -w -A OUTPUT -d 127.0.0.1 -j NETWORKING_PREP
ip6tables -w -N NETWORKING_PREP
ip6tables -w -A NETWORKING_PREP -p tcp --dport 19091 -j REJECT
ip6tables -w -A OUTPUT -d ::1 -j NETWORKING_PREP
iptables -w -t nat -I OUTPUT 1 -m owner --uid-owner 0 -j RETURN
iptables-nft -w -t nat -I OUTPUT 1 -m owner --uid-owner 0 -j RETURN
/probe network-state --id "$2"
/probe request --protocol tcp --target "$1" --id "$2" --duration 2s --timeout 300ms`, "prepare-network", target, id}}
	prep.SecurityContext.Capabilities.Add = []core.Capability{"NET_ADMIN", "NET_RAW"}
	first := core.Container{Name: "first-probe", Image: image, ImagePullPolicy: core.PullNever, SecurityContext: security(10000), Command: []string{"/bin/sh", "-ec"}, Args: []string{`/probe network-state --id "$2" --attempt-ipv6
/probe request --protocol tcp --target "$1" --id "$2" --duration 15s --timeout 300ms`, "first-probe", target, id}}
	app := core.Container{Name: "probe", Image: image, ImagePullPolicy: core.PullNever, SecurityContext: security(10000), Args: []string{"network-state", "--id", id, "--attempt-ipv6", "--idle"}}
	// Deliberately exercise direct traffic with the CNI's selected bypass UID.
	// This proves the foundation boundary independently of proxy authorization.
	resident := core.Container{Name: "istio-proxy", Image: image, ImagePullPolicy: core.PullNever, SecurityContext: security(10000), Args: []string{"idle"}}
	options := enrollment.Options{Network: n, Trusted: enrollment.TrustedSpec{InitContainers: []core.Container{*prep.DeepCopy()}, Containers: []core.Container{*resident.DeepCopy()}, NetworkInitContainers: []string{prep.Name}}}
	pod, err := enrollment.ExpandPod(&core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: n.Namespace, Annotations: map[string]string{"sidecar.istio.io/status": "{}"}}, Spec: core.PodSpec{ServiceAccountName: "default", RestartPolicy: core.RestartPolicyNever, AutomountServiceAccountToken: new(false), InitContainers: []core.Container{prep, first}, Containers: []core.Container{app, resident}}}, options)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(pod)
}
