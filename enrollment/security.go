package enrollment

import (
	"fmt"
	"path"
	"reflect"
	"strings"

	core "k8s.io/api/core/v1"
)

// Check the final composition, including generated initialization containers.
// Omission is deliberately not a guarantee of a restricted kernel profile.
func validateProfiles(p *core.Pod) error {
	for _, containers := range [][]core.Container{p.Spec.Containers, p.Spec.InitContainers} {
		for _, c := range containers {
			var seccomp *core.SeccompProfile
			var apparmor *core.AppArmorProfile
			secSource, appSource := "spec.securityContext.seccompProfile", "spec.securityContext.appArmorProfile"
			if p.Spec.SecurityContext != nil {
				seccomp = p.Spec.SecurityContext.SeccompProfile
				apparmor = p.Spec.SecurityContext.AppArmorProfile
			}
			if c.SecurityContext != nil {
				if c.SecurityContext.SeccompProfile != nil {
					seccomp = c.SecurityContext.SeccompProfile
					secSource = "container.securityContext.seccompProfile"
				}
				if c.SecurityContext.AppArmorProfile != nil {
					apparmor = c.SecurityContext.AppArmorProfile
					appSource = "container.securityContext.appArmorProfile"
				}
			}
			if seccomp != nil && seccomp.Type == core.SeccompProfileTypeUnconfined {
				return fmt.Errorf("%s: %s: effective Unconfined unsupported", c.Name, secSource)
			}
			key := "container.apparmor.security.beta.kubernetes.io/" + c.Name
			if value, ok := p.Annotations[key]; ok {
				legacy, err := legacyAppArmor(value)
				if err != nil {
					return fmt.Errorf("%s: metadata.annotations[%s]: %w", c.Name, key, err)
				}
				if apparmor != nil && !reflect.DeepEqual(apparmor, legacy) {
					return fmt.Errorf("%s: metadata.annotations[%s] conflicts with %s", c.Name, key, appSource)
				}
				apparmor = legacy
				appSource = "metadata.annotations[" + key + "]"
			}
			if apparmor != nil && apparmor.Type == core.AppArmorProfileTypeUnconfined {
				return fmt.Errorf("%s: %s: effective Unconfined unsupported", c.Name, appSource)
			}
		}
	}
	return nil
}

// Only enumerate Kubernetes v1.34 container defaults. Normalization is private,
// comparison-only, and never changes the caller's object or emitted resources.
func equivalentContainer(a, b core.Container) bool {
	return reflect.DeepEqual(defaultedContainer(a), defaultedContainer(b))
}
func defaultedContainer(input core.Container) *core.Container {
	c := input.DeepCopy()
	if c.ImagePullPolicy == "" {
		image, _, digest := strings.Cut(c.Image, "@")
		leaf := path.Base(image)
		_, tag, tagged := strings.Cut(leaf, ":")
		if tag == "latest" || (!tagged && !digest) {
			c.ImagePullPolicy = core.PullAlways
		} else {
			c.ImagePullPolicy = core.PullIfNotPresent
		}
	}
	if c.TerminationMessagePath == "" {
		c.TerminationMessagePath = "/dev/termination-log"
	}
	if c.TerminationMessagePolicy == "" {
		c.TerminationMessagePolicy = core.TerminationMessageReadFile
	}
	for _, probe := range []*core.Probe{c.StartupProbe, c.ReadinessProbe, c.LivenessProbe} {
		if probe == nil {
			continue
		}
		if probe.TimeoutSeconds == 0 {
			probe.TimeoutSeconds = 1
		}
		if probe.PeriodSeconds == 0 {
			probe.PeriodSeconds = 10
		}
		if probe.SuccessThreshold == 0 {
			probe.SuccessThreshold = 1
		}
		if probe.FailureThreshold == 0 {
			probe.FailureThreshold = 3
		}
		if probe.HTTPGet != nil {
			if probe.HTTPGet.Path == "" {
				probe.HTTPGet.Path = "/"
			}
			if probe.HTTPGet.Scheme == "" {
				probe.HTTPGet.Scheme = core.URISchemeHTTP
			}
		}
	}
	return c
}

func legacyAppArmor(value string) (*core.AppArmorProfile, error) {
	switch {
	case value == "runtime/default":
		return &core.AppArmorProfile{Type: core.AppArmorProfileTypeRuntimeDefault}, nil
	case value == "unconfined":
		return &core.AppArmorProfile{Type: core.AppArmorProfileTypeUnconfined}, nil
	case strings.HasPrefix(value, "localhost/") && len(value) > len("localhost/"):
		return &core.AppArmorProfile{Type: core.AppArmorProfileTypeLocalhost, LocalhostProfile: new(strings.TrimPrefix(value, "localhost/"))}, nil
	default:
		return nil, fmt.Errorf("unsupported AppArmor profile %q", value)
	}
}

func equivalentTrusted(actual, expected core.Container, annotations map[string]string) bool {
	// Kubernetes materializes legacy AppArmor annotations as structured fields.
	// Only that exact profile is equivalent; other security changes remain visible.
	if value, ok := annotations["container.apparmor.security.beta.kubernetes.io/"+expected.Name]; ok {
		profile, err := legacyAppArmor(value)
		if err != nil {
			return false
		}
		a, b := actual.DeepCopy(), expected.DeepCopy()
		if a.SecurityContext == nil || b.SecurityContext == nil || !reflect.DeepEqual(b.SecurityContext.AppArmorProfile, profile) {
			return false
		}
		if a.SecurityContext.AppArmorProfile == nil {
			a.SecurityContext.AppArmorProfile = profile
		}
		return equivalentContainer(*a, *b)
	}
	return equivalentContainer(actual, expected)
}
