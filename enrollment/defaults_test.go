package enrollment

import (
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"reflect"
	"testing"
)

func TestComparisonDefaults(t *testing.T) {
	for _, tt := range []struct {
		image  string
		policy core.PullPolicy
	}{
		{"proxy", core.PullAlways}, {"registry:5000/team/proxy", core.PullAlways}, {"proxy:latest", core.PullAlways},
		{"proxy:1.31.0", core.PullIfNotPresent}, {"proxy@sha256:abc", core.PullIfNotPresent}, {"proxy:latest@sha256:abc", core.PullAlways},
	} {
		t.Run(tt.image, func(t *testing.T) {
			original := core.Container{Image: tt.image, ReadinessProbe: &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: &core.HTTPGetAction{Port: intstr.FromInt32(15021)}}}}
			before := original.DeepCopy()
			explicit := original.DeepCopy()
			explicit.ImagePullPolicy = tt.policy
			explicit.TerminationMessagePath = "/dev/termination-log"
			explicit.TerminationMessagePolicy = core.TerminationMessageReadFile
			explicit.ReadinessProbe.TimeoutSeconds = 1
			explicit.ReadinessProbe.PeriodSeconds = 10
			explicit.ReadinessProbe.SuccessThreshold = 1
			explicit.ReadinessProbe.FailureThreshold = 3
			explicit.ReadinessProbe.HTTPGet.Path = "/"
			explicit.ReadinessProbe.HTTPGet.Scheme = core.URISchemeHTTP
			if !equivalentContainer(original, *explicit) {
				t.Fatal("API defaults not equivalent")
			}
			if !reflect.DeepEqual(&original, before) {
				t.Fatal("comparison mutated input")
			}
			explicit.ReadinessProbe.TimeoutSeconds = 2
			if equivalentContainer(original, *explicit) {
				t.Fatal("nondefault timeout ignored")
			}
		})
	}
	original := core.Container{Image: "proxy:1", Env: []core.EnvVar{{Name: "A"}, {Name: "B"}}}
	for _, change := range []func(*core.Container){
		func(c *core.Container) { c.Env[0], c.Env[1] = c.Env[1], c.Env[0] },
		func(c *core.Container) { c.ReadinessProbe = &core.Probe{} },
		func(c *core.Container) { c.SecurityContext = &core.SecurityContext{} },
		func(c *core.Container) { c.Args = []string{"extra"} },
	} {
		c := original.DeepCopy()
		change(c)
		if equivalentContainer(original, *c) {
			t.Fatal("nondefault fields discarded")
		}
	}
}
