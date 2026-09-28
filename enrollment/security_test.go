package enrollment_test

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
)

func TestEffectiveProfiles(t *testing.T) {
	for _, kind := range []string{"seccomp", "apparmor"} {
		for _, inherited := range []bool{false, true} {
			t.Run(kind+strconv.FormatBool(inherited), func(t *testing.T) {
				p, o := example()
				if inherited {
					p.Spec.SecurityContext = &core.PodSecurityContext{}
					if kind == "seccomp" {
						p.Spec.SecurityContext.SeccompProfile = &core.SeccompProfile{Type: core.SeccompProfileTypeUnconfined}
					} else {
						p.Spec.SecurityContext.AppArmorProfile = &core.AppArmorProfile{Type: core.AppArmorProfileTypeUnconfined}
					}
				} else {
					if kind == "seccomp" {
						p.Spec.Containers[0].SecurityContext.SeccompProfile = &core.SeccompProfile{Type: core.SeccompProfileTypeUnconfined}
					} else {
						p.Spec.Containers[0].SecurityContext.AppArmorProfile = &core.AppArmorProfile{Type: core.AppArmorProfileTypeUnconfined}
					}
				}
				got, err := enrollment.ExpandPod(p, o)
				if err == nil || got != nil {
					t.Fatal("unsafe effective profile accepted")
				}
			})
		}
	}
}
func safeProfile(s *core.SecurityContext, kind string) {
	if kind == "seccomp" {
		s.SeccompProfile = &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}
	} else {
		s.AppArmorProfile = &core.AppArmorProfile{Type: core.AppArmorProfileTypeRuntimeDefault}
	}
}

func TestAppArmorSources(t *testing.T) {
	for _, tt := range []struct {
		name, legacy string
		structured   *core.AppArmorProfile
		pod          *core.AppArmorProfile
		reject       bool
	}{
		{name: "omitted"},
		{name: "legacy default", legacy: "runtime/default"},
		{name: "equivalent", legacy: "runtime/default", structured: &core.AppArmorProfile{Type: core.AppArmorProfileTypeRuntimeDefault}},
		{name: "localhost equivalent", legacy: "localhost/custom", structured: &core.AppArmorProfile{Type: core.AppArmorProfileTypeLocalhost, LocalhostProfile: new("custom")}},
		{name: "legacy unconfined", legacy: "unconfined", reject: true},
		{name: "conflict", legacy: "unconfined", structured: &core.AppArmorProfile{Type: core.AppArmorProfileTypeRuntimeDefault}, reject: true},
		{name: "different local profiles", legacy: "localhost/other", structured: &core.AppArmorProfile{Type: core.AppArmorProfileTypeLocalhost, LocalhostProfile: new("custom")}, reject: true},
		{name: "pod contradiction", legacy: "localhost/custom", pod: &core.AppArmorProfile{Type: core.AppArmorProfileTypeRuntimeDefault}, reject: true},
		{name: "container override", structured: &core.AppArmorProfile{Type: core.AppArmorProfileTypeLocalhost, LocalhostProfile: new("custom")}, pod: &core.AppArmorProfile{Type: core.AppArmorProfileTypeRuntimeDefault}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, o := example()
			p.Spec.SecurityContext = &core.PodSecurityContext{AppArmorProfile: tt.pod}
			p.Spec.Containers[0].SecurityContext.AppArmorProfile = tt.structured
			if tt.legacy != "" {
				p.Annotations = map[string]string{"container.apparmor.security.beta.kubernetes.io/app": tt.legacy}
			}
			before := p.DeepCopy()
			got, err := enrollment.ExpandPod(p, o)
			if (err != nil) != tt.reject {
				t.Fatalf("err=%v", err)
			}
			if tt.reject && got != nil {
				t.Fatal("partial output")
			}
			if !reflect.DeepEqual(p, before) {
				t.Fatal("mutated input")
			}
		})
	}
}

func TestUnsupportedRuntimeAndNetworkSelection(t *testing.T) {
	for _, key := range []string{"runtimeClass", "k8s.v1.cni.cncf.io/networks", "v1.multus-cni.io/default-network"} {
		for _, value := range []string{"", "custom"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				p, o := example()
				if key == "runtimeClass" {
					p.Spec.RuntimeClassName = new(value)
				} else {
					p.Annotations = map[string]string{key: value}
				}
				got, err := enrollment.ExpandPod(p, o)
				if err == nil || got != nil {
					t.Fatal("unsupported selection accepted")
				}
			})
		}
	}
}

func TestAPIDefaultedValidation(t *testing.T) {
	p, o := example()
	p, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	p.Spec.InitContainers[0].TerminationMessagePath = "/dev/termination-log"
	p.Spec.InitContainers[0].TerminationMessagePolicy = core.TerminationMessageReadFile
	before := p.DeepCopy()
	got, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, before) || !reflect.DeepEqual(p, before) {
		t.Fatal("defaulted pod changed")
	}
	for _, tt := range []struct {
		name   string
		change func(*core.Container)
	}{
		{"image", func(c *core.Container) { c.Image = "other:latest" }},
		{"mount", func(c *core.Container) {
			c.VolumeMounts = []core.VolumeMount{{Name: "token", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount", ReadOnly: true}}
		}},
		{"args", func(c *core.Container) { c.Args = append(c.Args, "--extra") }},
		{"env", func(c *core.Container) { c.Env = append(c.Env, core.EnvVar{Name: "OTHER", Value: "true"}) }},
		{"security", func(c *core.Container) { c.SecurityContext.ReadOnlyRootFilesystem = new(false) }},
		{"pull policy", func(c *core.Container) { c.ImagePullPolicy = core.PullAlways }},
		{"message path", func(c *core.Container) { c.TerminationMessagePath = "/tmp/other" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			bad := p.DeepCopy()
			tt.change(&bad.Spec.InitContainers[0])
			got, err := enrollment.ExpandPod(bad, o)
			if err == nil || got != nil {
				t.Fatal("real override accepted")
			}
		})
	}
}
