package enrollment_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func example() (*core.Pod, enrollment.Options) {
	sc := func(uid int64) *core.SecurityContext {
		return &core.SecurityContext{RunAsUser: new(uid), RunAsGroup: new(uid), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}
	}
	probe := &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: &core.HTTPGetAction{Path: "/healthz/ready", Port: intstr.FromInt32(15021)}}}
	p := &core.Pod{ObjectMeta: meta.ObjectMeta{Namespace: "tenant", GenerateName: "workload-", Labels: map[string]string{"example.test/enabled": "true", "business": "kept"}}, Spec: core.PodSpec{ServiceAccountName: "worker", Containers: []core.Container{{Name: "app", Image: "app:test", SecurityContext: sc(10000)}}, InitContainers: []core.Container{{Name: enrollment.ProxyName, Image: "istio/proxyv2:1.31.0", RestartPolicy: new(core.ContainerRestartPolicyAlways), SecurityContext: sc(1337), StartupProbe: probe.DeepCopy(), ReadinessProbe: probe.DeepCopy()}, {Name: "business-init", Image: "init:test", SecurityContext: sc(10000)}}}}
	o := enrollment.Options{EnabledLabel: "example.test/enabled", Network: enrollment.Network{Namespace: "tenant", Binding: "binding-a", Control: &enrollment.Istiod{IPv4: "10.96.0.12", Hostname: "istiod.istio-system.svc", Peer: enrollment.Peer{Namespace: "istio-system", PodLabels: map[string]string{"app": "istiod"}}}}}
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
	if a.Spec.InitContainers[0].Name != "istio-validation" || a.Spec.InitContainers[1].Name != enrollment.ProxyName || a.Spec.InitContainers[2].Name != "business-init" {
		t.Fatal("startup order changed")
	}
	if a.Annotations["sidecar.istio.io/inject"] != "" {
		t.Fatal("CNI disabled")
	}
}

func TestPublicInputsCannotOverrideContract(t *testing.T) {
	tests := map[string]func(*core.Pod, *enrollment.Options){
		"missing proxy": func(p *core.Pod, _ *enrollment.Options) { p.Spec.InitContainers = nil },
		"ordinary sidecar": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers = append(p.Spec.Containers, p.Spec.InitContainers[0])
			p.Spec.InitContainers = nil
		},
		"wrong proxy uid": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].SecurityContext.RunAsUser = new(int64(1001))
		},
		"app proxy uid": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.RunAsUser = new(int64(1337))
		},
		"app proxy gid": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.RunAsGroup = new(int64(1337))
		},
		"missing app gid":  func(p *core.Pod, _ *enrollment.Options) { p.Spec.Containers[0].SecurityContext.RunAsGroup = nil },
		"missing init gid": func(p *core.Pod, _ *enrollment.Options) { p.Spec.InitContainers[1].SecurityContext.RunAsGroup = nil },
		"dns listener override": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].Env = []core.EnvVar{{Name: "DNS_PROXY_ADDR", Value: "127.0.0.1:16053"}}
		},
		"tls name override": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].Env = []core.EnvVar{{Name: "ISTIOD_SAN", Value: "wrong.test"}}
		},
		"dns listener valueFrom": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].Env = []core.EnvVar{{Name: "DNS_PROXY_ADDR", ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{FieldPath: "metadata.name"}}}}
		},
		"root app": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.RunAsUser = new(int64(0))
		},
		"net admin": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []core.Capability{"NET_ADMIN"}
		},
		"privileged": func(p *core.Pod, _ *enrollment.Options) { p.Spec.Containers[0].SecurityContext.Privileged = new(true) },
		"escalation": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = new(true)
		},
		"host network": func(p *core.Pod, _ *enrollment.Options) { p.Spec.HostNetwork = true },
		"host pid":     func(p *core.Pod, _ *enrollment.Options) { p.Spec.HostPID = true },
		"shared pid":   func(p *core.Pod, _ *enrollment.Options) { p.Spec.ShareProcessNamespace = new(true) },
		"supplemental group": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.SecurityContext = &core.PodSecurityContext{SupplementalGroups: []int64{1337}}
		},
		"host mount": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Volumes = []core.Volume{{Name: "host", VolumeSource: core.VolumeSource{HostPath: &core.HostPathVolumeSource{Path: "/"}}}}
		},
		"business init before proxy": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0], p.Spec.InitContainers[1] = p.Spec.InitContainers[1], p.Spec.InitContainers[0]
		},
		"trusted init not unrestricted": func(p *core.Pod, o *enrollment.Options) {
			p.Spec.InitContainers[0], p.Spec.InitContainers[1] = p.Spec.InitContainers[1], p.Spec.InitContainers[0]
			o.TrustedInit = []string{"business-init"}
			p.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []core.Capability{"NET_ADMIN"}
		},
		"startup gate missing": func(p *core.Pod, _ *enrollment.Options) { p.Spec.InitContainers[0].StartupProbe = nil },
		"dns env disabled": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].Env = []core.EnvVar{{Name: "ISTIO_META_DNS_CAPTURE", Value: "false"}}
		},
		"config disables dns": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].Env = []core.EnvVar{{Name: "PROXY_CONFIG", Value: `{"proxyMetadata":{"ISTIO_META_DNS_CAPTURE":"false"}}`}}
		},
		"tls bootstrap changed": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].Env = []core.EnvVar{{Name: "PROXY_CONFIG", Value: `{"controlPlaneAuthPolicy":"NONE"}`}}
		},
		"envFrom": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0].EnvFrom = []core.EnvFromSource{{Prefix: "HIDDEN"}}
		},
		"inject false": func(p *core.Pod, _ *enrollment.Options) {
			p.Annotations = map[string]string{"sidecar.istio.io/inject": "false"}
		},
		"inject true label": func(p *core.Pod, _ *enrollment.Options) { p.Labels["sidecar.istio.io/inject"] = "true" },
		"exclusion annotation": func(p *core.Pod, _ *enrollment.Options) {
			p.Annotations = map[string]string{"traffic.sidecar.istio.io/excludeOutboundPorts": "443"}
		},
		"reroute annotation": func(p *core.Pod, _ *enrollment.Options) {
			p.Annotations = map[string]string{"istio.io/reroute-virtual-interfaces": "eth0"}
		},
		"second config channel": func(p *core.Pod, _ *enrollment.Options) {
			p.Annotations = map[string]string{"proxy.istio.io/config": "{}"}
		},
		"wrong binding": func(p *core.Pod, _ *enrollment.Options) { p.Labels[enrollment.BindingLabel] = "other" },
		"address conflict": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.HostAliases = []core.HostAlias{{IP: "10.96.0.13", Hostnames: []string{"istiod.istio-system.svc"}}}
		},
		"namespace mismatch": func(_ *core.Pod, o *enrollment.Options) { o.Network.Namespace = "other" },
		"control missing":    func(_ *core.Pod, o *enrollment.Options) { o.Network.Control = nil },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			p, o := example()
			change(p, &o)
			result, err := enrollment.ExpandPod(p, o)
			if err == nil || result != nil {
				t.Fatal("invalid input accepted or partial result returned")
			}
		})
	}
}

func TestPolicyLimitsAndBinding(t *testing.T) {
	_, o := example()
	o.Network.Control = nil
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
