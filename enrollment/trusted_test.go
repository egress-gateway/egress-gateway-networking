package enrollment_test

import (
	"reflect"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
)

func prepared() (*core.Pod, enrollment.Options) {
	p, o := example()
	volume := core.Volume{Name: "private", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}}
	prep := core.Container{Name: "prepare", Image: "prepare:v1", Command: []string{"prepare"}, SecurityContext: security(0), VolumeMounts: []core.VolumeMount{{Name: volume.Name, MountPath: "/private"}}}
	prep.SecurityContext.Capabilities.Add = []core.Capability{"CHOWN", "FOWNER"}
	p.Spec.InitContainers = append([]core.Container{prep}, p.Spec.InitContainers...)
	p.Spec.Volumes = []core.Volume{volume}
	o.Trusted.InitContainers = append([]core.Container{*prep.DeepCopy()}, o.Trusted.InitContainers...)
	o.Trusted.Volumes = []core.Volume{*volume.DeepCopy()}
	return p, o
}
func TestTrustedInputsBoundIndependently(t *testing.T) {
	changes := map[string]func(*core.Container){
		"image":   func(c *core.Container) { c.Image = "other:v1" },
		"command": func(c *core.Container) { c.Command = []string{"other"} },
		"args":    func(c *core.Container) { c.Args = []string{"other"} },
		"env":     func(c *core.Container) { c.Env = []core.EnvVar{{Name: "A", Value: "other"}} },
		"envFrom": func(c *core.Container) {
			c.EnvFrom = []core.EnvFromSource{{ConfigMapRef: &core.ConfigMapEnvSource{LocalObjectReference: core.LocalObjectReference{Name: "other"}}}}
		},
		"valueFrom": func(c *core.Container) {
			c.Env = []core.EnvVar{{Name: "A", ValueFrom: &core.EnvVarSource{SecretKeyRef: &core.SecretKeySelector{LocalObjectReference: core.LocalObjectReference{Name: "other"}, Key: "key"}}}}
		},
		"directory": func(c *core.Container) { c.WorkingDir = "/other" },
		"mount":     func(c *core.Container) { c.VolumeMounts[0].MountPath = "/other" },
		"subpath":   func(c *core.Container) { c.VolumeMounts[0].SubPath = "other" },
		"device": func(c *core.Container) {
			c.VolumeDevices = []core.VolumeDevice{{Name: "private", DevicePath: "/dev/other"}}
		},
		"security": func(c *core.Container) { c.SecurityContext.RunAsUser = new(int64(5)) },
		"lifecycle": func(c *core.Container) {
			c.Lifecycle = &core.Lifecycle{PreStop: &core.LifecycleHandler{Exec: &core.ExecAction{Command: []string{"other"}}}}
		},
		"probe": func(c *core.Container) {
			c.StartupProbe = &core.Probe{ProbeHandler: core.ProbeHandler{Exec: &core.ExecAction{Command: []string{"other"}}}}
		},
		"restart":     func(c *core.Container) { c.RestartPolicy = new(core.ContainerRestartPolicyAlways) },
		"termination": func(c *core.Container) { c.TerminationMessagePath = "/other" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p, o := prepared()
			change(&p.Spec.InitContainers[0])
			if got, err := enrollment.ExpandPod(p, o); err == nil || got != nil {
				t.Fatal("trusted execution substitution accepted")
			}
		})
	}
	p, o := prepared()
	before := p.DeepCopy()
	if _, err := enrollment.ExpandPod(p, o); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, before) {
		t.Fatal("input changed")
	}
	p.Spec.Volumes[0].VolumeSource = core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "other"}}
	if _, err := enrollment.ExpandPod(p, o); err == nil {
		t.Fatal("source substitution accepted")
	}
}
func TestTrustDoesNotGrantNetworkPrivileges(t *testing.T) {
	for _, cap := range []core.Capability{"NET_ADMIN", "NET_RAW", "SYS_ADMIN"} {
		t.Run(string(cap), func(t *testing.T) {
			p, o := prepared()
			p.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []core.Capability{cap}
			o.Trusted.InitContainers[0] = *p.Spec.InitContainers[0].DeepCopy()
			if _, err := enrollment.ExpandPod(p, o); err == nil {
				t.Fatal("trusted privilege ceiling bypassed")
			}
		})
	}
	p, o := prepared()
	o.Trusted = enrollment.TrustedSpec{}
	p.Annotations = map[string]string{"trusted": "true"}
	if _, err := enrollment.ExpandPod(p, o); err == nil {
		t.Fatal("self-designation accepted")
	}
	p, o = prepared()
	p.Spec.InitContainers[0].RestartPolicy = new(core.ContainerRestartPolicyAlways)
	o.Trusted.InitContainers[0] = *p.Spec.InitContainers[0].DeepCopy()
	if _, err := enrollment.ExpandPod(p, o); err == nil {
		t.Fatal("persistent root preparation accepted")
	}
}
func TestFoundationNeedsNoRuntime(t *testing.T) {
	p, o := example()
	p.Spec.InitContainers = nil
	o.Trusted = enrollment.TrustedSpec{}
	p.Spec.Containers[0].SecurityContext = security(1337)
	got, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Spec, p.Spec) {
		t.Fatal("unexpected injection")
	}
}

func TestTrustedProfileCannotBeReplacedByAnnotation(t *testing.T) {
	p, o := prepared()
	expected := &core.AppArmorProfile{Type: core.AppArmorProfileTypeRuntimeDefault}
	p.Spec.InitContainers[0].SecurityContext.AppArmorProfile = expected.DeepCopy()
	o.Trusted.InitContainers[0].SecurityContext.AppArmorProfile = expected.DeepCopy()
	p.Annotations = map[string]string{"container.apparmor.security.beta.kubernetes.io/prepare": "runtime/default"}
	p.Spec.InitContainers[0].SecurityContext.AppArmorProfile = nil
	if _, err := enrollment.ExpandPod(p, o); err != nil {
		t.Fatal("equivalent legacy profile rejected", err)
	}
	p.Annotations["container.apparmor.security.beta.kubernetes.io/prepare"] = "localhost/other"
	if got, err := enrollment.ExpandPod(p, o); err == nil || got != nil {
		t.Fatal("annotation replaced independent trusted profile")
	}
}
func TestTrustedMissingDuplicateAndWrongRole(t *testing.T) {
	for name, change := range map[string]func(*core.Pod, *enrollment.Options){
		"missing": func(p *core.Pod, o *enrollment.Options) { p.Spec.InitContainers = p.Spec.InitContainers[1:] },
		"duplicate": func(p *core.Pod, o *enrollment.Options) {
			p.Spec.InitContainers = append(p.Spec.InitContainers, p.Spec.InitContainers[0])
		},
		"expected duplicate": func(p *core.Pod, o *enrollment.Options) {
			o.Trusted.InitContainers = append(o.Trusted.InitContainers, o.Trusted.InitContainers[0])
		},
		"wrong role": func(p *core.Pod, o *enrollment.Options) {
			p.Spec.Containers = append(p.Spec.Containers, p.Spec.InitContainers[0])
			p.Spec.InitContainers = p.Spec.InitContainers[1:]
		},
		"missing volume":    func(p *core.Pod, o *enrollment.Options) { p.Spec.Volumes = nil },
		"undeclared volume": func(p *core.Pod, o *enrollment.Options) { o.Trusted.Volumes = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p, o := prepared()
			change(p, &o)
			if got, err := enrollment.ExpandPod(p, o); err == nil || got != nil {
				t.Fatal("invalid trusted composition accepted")
			}
		})
	}
}
