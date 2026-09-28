package enrollment_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func security(uid int64) *core.SecurityContext {
	return &core.SecurityContext{RunAsUser: new(uid), RunAsGroup: new(uid), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}
}
func example() (*core.Pod, enrollment.Options) {
	p := &core.Pod{ObjectMeta: meta.ObjectMeta{Namespace: "tenant", GenerateName: "workload-", Labels: map[string]string{"business": "kept"}}, Spec: core.PodSpec{ServiceAccountName: "worker", Containers: []core.Container{{Name: "app", Image: "app:test", SecurityContext: security(10000)}}, InitContainers: []core.Container{{Name: "runtime", Image: "runtime:test", RestartPolicy: new(core.ContainerRestartPolicyAlways), SecurityContext: security(2000)}, {Name: "business-init", Image: "init:test", SecurityContext: security(10000)}}}}
	o := enrollment.Options{Network: enrollment.Network{Namespace: "tenant", Binding: "binding-a"}, Trusted: enrollment.TrustedSpec{InitContainers: []core.Container{*p.Spec.InitContainers[0].DeepCopy()}}}
	return p, o
}

func TestAdmissionExpansionIsPureIdempotentAndPreservesBusiness(t *testing.T) {
	p, o := example()
	before := p.DeepCopy()
	a, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, before) {
		t.Fatal("caller input mutated")
	}
	b, err := enrollment.ExpandPod(a, o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("repeat expansion changed result")
	}
	if a.UID != "" || a.Name != "" || a.GenerateName != p.GenerateName || a.Labels["business"] != "kept" || !reflect.DeepEqual(a.Spec.Containers, p.Spec.Containers) {
		t.Fatal("lost admission/business fields")
	}
	if !reflect.DeepEqual(a.Spec, p.Spec) || !reflect.DeepEqual(a.Annotations, p.Annotations) {
		t.Fatal("platform helper changed component execution")
	}

}

func TestPublicInputsCannotOverrideContract(t *testing.T) {
	tests := map[string]func(*core.Pod, *enrollment.Options){
		"root app": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.RunAsUser = new(int64(0))
		},
		"missing group": func(p *core.Pod, _ *enrollment.Options) { p.Spec.Containers[0].SecurityContext.RunAsGroup = nil },
		"net admin": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []core.Capability{"NET_ADMIN"}
		},
		"host network": func(p *core.Pod, _ *enrollment.Options) { p.Spec.HostNetwork = true },
		"host pid":     func(p *core.Pod, _ *enrollment.Options) { p.Spec.HostPID = true },
		"host ipc":     func(p *core.Pod, _ *enrollment.Options) { p.Spec.HostIPC = true },
		"shared pid":   func(p *core.Pod, _ *enrollment.Options) { p.Spec.ShareProcessNamespace = new(true) },
		"root group": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.SecurityContext = &core.PodSecurityContext{SupplementalGroups: []int64{0}}
		},
		"host mount": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Volumes = []core.Volume{{Name: "host", VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/"}}}}
		},
		"binding":         func(p *core.Pod, _ *enrollment.Options) { p.Labels[enrollment.BindingLabel] = "other" },
		"namespace":       func(_ *core.Pod, o *enrollment.Options) { o.Network.Namespace = "other" },
		"missing trusted": func(p *core.Pod, _ *enrollment.Options) { p.Spec.InitContainers = p.Spec.InitContainers[1:] },
		"privileged":      func(p *core.Pod, _ *enrollment.Options) { p.Spec.Containers[0].SecurityContext.Privileged = new(true) },
		"escalation": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = new(true)
		},
		"sysctl": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.SecurityContext = &core.PodSecurityContext{Sysctls: []core.Sysctl{{Name: "net.ipv4.ip_forward", Value: "1"}}}
		},
		"ephemeral": func(p *core.Pod, _ *enrollment.Options) { p.Spec.EphemeralContainers = []core.EphemeralContainer{{}} },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, o := example()
			change(p, &o)
			result, err := enrollment.ExpandPod(p, o)
			if err == nil || result != nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func TestPolicyLimitsAndBinding(t *testing.T) {
	_, o := example()
	p, err := enrollment.ExpandPolicy(o.Network)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.Egress) != 0 || !reflect.DeepEqual(p.Labels, p.Spec.PodSelector.MatchLabels) {
		t.Fatal("default is not binding-selected deny")
	}
	for _, peer := range []enrollment.Peer{{}, {Namespace: "all"}, {IPv4: "0.0.0.0/0"}, {IPv4: "::1"}, {IPv4: "127.0.0.1"}, {IPv4: "10.0.0.1", Namespace: "other"}} {
		o.Network.DNS = []enrollment.Peer{peer}
		if p, err := enrollment.ExpandPolicy(o.Network); err == nil || p != nil {
			t.Fatalf("unsafe peer accepted: %+v", peer)
		}
	}
	o.Network.DNS = []enrollment.Peer{{IPv4: "10.0.0.53"}}
	p, err = enrollment.ExpandPolicy(o.Network)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.Egress) != 1 || p.Spec.Egress[0].To[0].IPBlock.CIDR != "10.0.0.53/32" || len(p.Spec.Egress[0].Ports) != 2 {
		t.Fatal("not precise DNS allowance")
	}
	o.Network.Forward = []enrollment.TCPDestination{{Peer: enrollment.Peer{IPv4: "10.0.0.1"}, Ports: []int32{53}}}
	if _, err = enrollment.ExpandPolicy(o.Network); err == nil {
		t.Fatal("DNS disguised as forwarding accepted")
	}
}

func TestChangingNetworkValuesDoesNotChangeCapture(t *testing.T) {
	p, o := example()
	a, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	o.Network.Binding = "binding-b"
	o.Network.Forward = []enrollment.TCPDestination{{Peer: enrollment.Peer{IPv4: "10.0.0.99"}, Ports: []int32{8443}}}
	o.Network.DNS = []enrollment.Peer{{IPv4: "10.0.0.53"}}
	b, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Spec, b.Spec) || !reflect.DeepEqual(a.Annotations, b.Annotations) {
		t.Fatal("allowance changed immutable capture")
	}
	data, _ := json.Marshal(b)
	if len(data) == 0 {
		t.Fatal("missing generated Pod")
	}
}

func TestApplicationIdentityCanInheritSafePodGroup(t *testing.T) {
	p, o := example()
	p.Spec.SecurityContext = &core.PodSecurityContext{RunAsGroup: new(int64(10000))}
	p.Spec.Containers[0].SecurityContext.RunAsGroup = nil
	p.Spec.InitContainers[1].SecurityContext.RunAsGroup = nil
	if _, err := enrollment.ExpandPod(p, o); err != nil {
		t.Fatal(err)
	}
}
