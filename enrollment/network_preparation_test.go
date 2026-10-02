package enrollment_test

import (
	"reflect"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
)

func networkPrepared() (*core.Pod, enrollment.Options) {
	p, o := prepared()
	p.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []core.Capability{"NET_ADMIN", "NET_RAW"}
	o.Trusted.InitContainers[0] = *p.Spec.InitContainers[0].DeepCopy()
	o.Trusted.NetworkInitContainers = []string{"prepare"}
	return p, o
}

func TestNetworkPreparationRequiresIndependentAuthorization(t *testing.T) {
	p, o := networkPrepared()
	before := p.DeepCopy()
	got, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, before) || !reflect.DeepEqual(got.Spec, before.Spec) {
		t.Fatal("authorization changed caller-owned execution")
	}
	again, err := enrollment.ExpandPod(got, o)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("repeat expansion changed the result: %v", err)
	}
	for name, change := range map[string]func(*core.Pod, *enrollment.Options){
		"default envelope": func(_ *core.Pod, o *enrollment.Options) { o.Trusted.NetworkInitContainers = nil },
		"unknown name":     func(_ *core.Pod, o *enrollment.Options) { o.Trusted.NetworkInitContainers = []string{"absent"} },
		"duplicate authorization": func(_ *core.Pod, o *enrollment.Options) {
			o.Trusted.NetworkInitContainers = []string{"prepare", "prepare"}
		},
		"business self designation": func(p *core.Pod, o *enrollment.Options) {
			o.Trusted.InitContainers = o.Trusted.InitContainers[1:]
			p.Annotations = map[string]string{"networking.egress/network-init": "prepare"}
		},
		"image substitution":   func(p *core.Pod, _ *enrollment.Options) { p.Spec.InitContainers[0].Image = "untrusted:v1" },
		"command substitution": func(p *core.Pod, _ *enrollment.Options) { p.Spec.InitContainers[0].Command = []string{"other"} },
		"native sidecar": func(p *core.Pod, o *enrollment.Options) {
			p.Spec.InitContainers[0].RestartPolicy = new(core.ContainerRestartPolicyAlways)
			o.Trusted.InitContainers[0] = *p.Spec.InitContainers[0].DeepCopy()
		},
		"regular container": func(p *core.Pod, o *enrollment.Options) {
			p.Spec.Containers = append(p.Spec.Containers, p.Spec.InitContainers[0])
			p.Spec.InitContainers = p.Spec.InitContainers[1:]
			o.Trusted.Containers = append(o.Trusted.Containers, o.Trusted.InitContainers[0])
			o.Trusted.InitContainers = o.Trusted.InitContainers[1:]
		},
		"late after resident": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0], p.Spec.InitContainers[1] = p.Spec.InitContainers[1], p.Spec.InitContainers[0]
		},
		"late after business init": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.InitContainers[0], p.Spec.InitContainers[2] = p.Spec.InitContainers[2], p.Spec.InitContainers[0]
		},
		"additional capability": func(p *core.Pod, o *enrollment.Options) {
			p.Spec.InitContainers[0].SecurityContext.Capabilities.Add = append(p.Spec.InitContainers[0].SecurityContext.Capabilities.Add, "SYS_ADMIN")
			o.Trusted.InitContainers[0] = *p.Spec.InitContainers[0].DeepCopy()
		},
		"business capability": func(p *core.Pod, _ *enrollment.Options) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []core.Capability{"NET_RAW"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, o := networkPrepared()
			change(p, &o)
			if got, err := enrollment.ExpandPod(p, o); err == nil || got != nil {
				t.Fatal("invalid network preparation authorization accepted")
			}
		})
	}
}
