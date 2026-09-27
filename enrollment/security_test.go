package enrollment_test

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
)

func TestEffectiveProfiles(t *testing.T) {
	for _, kind := range []string{"seccomp", "apparmor"} {
		for _, role := range []string{"app", "business-init", "istio-proxy", "prepare", "istio-validation"} {
			for _, inherited := range []bool{false, true} {
				if role == "istio-validation" && kind == "seccomp" && !inherited {
					continue
				}
				t.Run(kind+"/"+role+"/inherited="+strconv.FormatBool(inherited), func(t *testing.T) {
					p, o := example()
					if role == "prepare" {
						c := *p.Spec.Containers[0].DeepCopy()
						c.Name = role
						p.Spec.InitContainers = append([]core.Container{c}, p.Spec.InitContainers...)
						o.TrustedInit = []string{role}
					}
					// The generated validation container must also be checked after composition.
					if role == "istio-validation" && !inherited {
						p.Annotations = map[string]string{"container.apparmor.security.beta.kubernetes.io/istio-validation": "unconfined"}
					}
					set := func(s *core.SecurityContext) {
						if kind == "seccomp" {
							s.SeccompProfile = &core.SeccompProfile{Type: core.SeccompProfileTypeUnconfined}
						} else {
							s.AppArmorProfile = &core.AppArmorProfile{Type: core.AppArmorProfileTypeUnconfined}
						}
					}
					if inherited {
						p.Spec.SecurityContext = &core.PodSecurityContext{}
						if kind == "seccomp" {
							p.Spec.SecurityContext.SeccompProfile = &core.SeccompProfile{Type: core.SeccompProfileTypeUnconfined}
						} else {
							p.Spec.SecurityContext.AppArmorProfile = &core.AppArmorProfile{Type: core.AppArmorProfileTypeUnconfined}
						}
						// Keep other declared containers safe so the error names the intended owner.
						for i := range p.Spec.Containers {
							if p.Spec.Containers[i].Name != role {
								safeProfile(p.Spec.Containers[i].SecurityContext, kind)
							}
						}
						for i := range p.Spec.InitContainers {
							if p.Spec.InitContainers[i].Name != role {
								safeProfile(p.Spec.InitContainers[i].SecurityContext, kind)
							}
						}
					} else {
						for i := range p.Spec.Containers {
							if p.Spec.Containers[i].Name == role {
								set(p.Spec.Containers[i].SecurityContext)
							}
						}
						for i := range p.Spec.InitContainers {
							if p.Spec.InitContainers[i].Name == role {
								set(p.Spec.InitContainers[i].SecurityContext)
							}
						}
					}
					want := role
					if inherited && role != "app" {
						want = "istio-validation"
					}
					before := p.DeepCopy()
					got, err := enrollment.ExpandPod(p, o)
					if got != nil || err == nil || !strings.Contains(err.Error(), want) {
						t.Fatalf("expected rejection naming %s: pod=%v err=%v", role, got != nil, err)
					}
					if !reflect.DeepEqual(p, before) {
						t.Fatal("input mutated")
					}
				})
			}
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

func TestProxyType(t *testing.T) {
	for _, tt := range []struct {
		name          string
		command, args []string
		reject        bool
	}{
		{name: "image entrypoint"},
		{name: "sidecar", args: []string{"proxy", "sidecar"}},
		{name: "router", args: []string{"proxy", "router"}, reject: true},
		{name: "unknown", args: []string{"proxy", "other"}, reject: true},
		{name: "explicit pilot", command: []string{"/usr/local/bin/pilot-agent"}, args: []string{"proxy", "router"}, reject: true},
		{name: "split command", command: []string{"pilot-agent", "proxy"}, args: []string{"router"}, reject: true},
		{name: "command router", command: []string{"pilot-agent", "proxy", "router"}, reject: true},
		{name: "root flag router", command: []string{"pilot-agent", "--log_output_level=all:warning", "proxy", "router"}, reject: true},
		{name: "root flag sidecar", command: []string{"pilot-agent", "--log_output_level=all:warning", "proxy", "sidecar"}},
		{name: "ambiguous root flag", command: []string{"pilot-agent", "--log_output_level", "all:warning", "proxy", "router"}, reject: true},
		{name: "sidecar command", command: []string{"pilot-agent", "proxy", "sidecar"}},
		{name: "unrelated word", args: []string{"proxy", "sidecar", "--domain", "router.test"}},
		{name: "wrapper", command: []string{"custom-wrapper"}, args: []string{"router"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p, o := example()
			p.Spec.InitContainers[0].Command = tt.command
			p.Spec.InitContainers[0].Args = tt.args
			got, err := enrollment.ExpandPod(p, o)
			if (err != nil) != tt.reject {
				t.Fatalf("err=%v", err)
			}
			if tt.reject && got != nil {
				t.Fatal("partial output")
			}
		})
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
