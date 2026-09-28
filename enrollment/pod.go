package enrollment

import (
	"fmt"
	"reflect"
	"slices"

	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// TrustedSpec is supplied independently by the platform, never inferred from a
// workload. It binds execution inputs, not the integrity of referenced objects.
// The caller owns code/configuration trust and final admission/write authority.
type TrustedSpec struct {
	InitContainers []core.Container `json:"initContainers,omitempty"`
	Containers     []core.Container `json:"containers,omitempty"`
	Volumes        []core.Volume    `json:"volumes,omitempty"`
}

type Options struct {
	Network Network     `json:"network"`
	Trusted TrustedSpec `json:"trusted,omitzero"`
}

// ExpandPod checks an already assembled Pod and binds the network allowance.
// It neither injects components nor changes their order. Failure returns no Pod.
func ExpandPod(input *core.Pod, o Options) (*core.Pod, error) {
	if input == nil {
		return nil, fmt.Errorf("pod: required")
	}
	policy, err := ExpandPolicy(o.Network)
	if err != nil {
		return nil, err
	}
	if input.Namespace != o.Network.Namespace {
		return nil, fmt.Errorf("metadata.namespace: must match network namespace")
	}
	if input.Spec.ServiceAccountName == "" || len(validation.IsDNS1123Subdomain(input.Spec.ServiceAccountName)) != 0 {
		return nil, fmt.Errorf("spec.serviceAccountName: explicit valid identity required")
	}
	p := input.DeepCopy()
	if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC || p.Spec.ShareProcessNamespace != nil && *p.Spec.ShareProcessNamespace {
		return nil, fmt.Errorf("spec: shared host/process namespaces are unsupported")
	}
	if p.Spec.RuntimeClassName != nil {
		return nil, fmt.Errorf("spec.runtimeClassName: unsupported runtime selection")
	}
	for _, key := range []string{"k8s.v1.cni.cncf.io/networks", "v1.multus-cni.io/default-network"} {
		if _, ok := p.Annotations[key]; ok {
			return nil, fmt.Errorf("metadata.annotations[%s]: unsupported network selection", key)
		}
	}
	if len(p.Spec.EphemeralContainers) != 0 {
		return nil, fmt.Errorf("spec.ephemeralContainers: unsupported")
	}
	if s := p.Spec.SecurityContext; s != nil {
		if s.RunAsUser != nil && *s.RunAsUser == 0 || s.RunAsGroup != nil && *s.RunAsGroup == 0 || s.FSGroup != nil && *s.FSGroup == 0 || slices.Contains(s.SupplementalGroups, int64(0)) {
			return nil, fmt.Errorf("spec.securityContext: application must not inherit root identity/group")
		}
		if len(s.Sysctls) != 0 {
			return nil, fmt.Errorf("spec.securityContext.sysctls: unsupported network override")
		}
	}
	volumes := map[string]core.Volume{}
	for _, v := range p.Spec.Volumes {
		if _, ok := volumes[v.Name]; ok {
			return nil, fmt.Errorf("spec.volumes[%s]: duplicate", v.Name)
		}
		if v.HostPath != nil {
			return nil, fmt.Errorf("spec.volumes[%s]: hostPath unsupported", v.Name)
		}
		volumes[v.Name] = v
	}
	expectedVolumes := map[string]core.Volume{}
	for _, v := range o.Trusted.Volumes {
		if _, ok := expectedVolumes[v.Name]; ok {
			return nil, fmt.Errorf("trusted.volumes[%s]: duplicate", v.Name)
		}
		actual, ok := volumes[v.Name]
		if !ok || !reflect.DeepEqual(actual, v) {
			return nil, fmt.Errorf("spec.volumes[%s]: does not match trusted source", v.Name)
		}
		expectedVolumes[v.Name] = v
	}
	type expectation struct {
		container core.Container
		init      bool
	}
	expected := map[string]expectation{}
	usedVolumes := map[string]bool{}
	for index, group := range [][]core.Container{o.Trusted.InitContainers, o.Trusted.Containers} {
		for _, c := range group {
			if c.Name == "" {
				return nil, fmt.Errorf("trusted: container name required")
			}
			if _, ok := expected[c.Name]; ok {
				return nil, fmt.Errorf("trusted[%s]: duplicate", c.Name)
			}
			expected[c.Name] = expectation{c, index == 0}
			names := []string{}
			for _, m := range c.VolumeMounts {
				names = append(names, m.Name)
			}
			for _, d := range c.VolumeDevices {
				names = append(names, d.Name)
			}
			for _, name := range names {
				if _, ok := expectedVolumes[name]; !ok {
					return nil, fmt.Errorf("trusted[%s].volumes[%s]: independent source declaration required", c.Name, name)
				}
				usedVolumes[name] = true
			}
		}
	}
	for name := range expectedVolumes {
		if !usedVolumes[name] {
			return nil, fmt.Errorf("trusted.volumes[%s]: not referenced by trusted components", name)
		}
	}
	seen := map[string]bool{}
	for index, group := range [][]core.Container{p.Spec.InitContainers, p.Spec.Containers} {
		for _, c := range group {
			if c.Name == "" || seen[c.Name] {
				return nil, fmt.Errorf("spec.containers[%s]: missing or duplicate name", c.Name)
			}
			seen[c.Name] = true
			prep := false
			if e, ok := expected[c.Name]; ok {
				if e.init != (index == 0) || !equivalentTrusted(c, e.container, p.Annotations) {
					return nil, fmt.Errorf("spec.containers[%s]: execution specification does not match trusted input", c.Name)
				}
				prep = index == 0 && c.RestartPolicy == nil
				delete(expected, c.Name)
			}
			if err := validateSecurity(c, p.Spec.SecurityContext, prep); err != nil {
				return nil, err
			}
		}
	}
	if len(expected) > 0 {
		return nil, fmt.Errorf("trusted: declared components missing from Pod")
	}
	if err := validateProfiles(p); err != nil {
		return nil, err
	}
	if p.Labels == nil {
		p.Labels = map[string]string{}
	}
	for k, v := range policy.Labels {
		if actual, ok := p.Labels[k]; ok && actual != v {
			return nil, fmt.Errorf("metadata.labels[%s]: conflicts with network binding", k)
		}
		p.Labels[k] = v
	}
	return p, nil
}

func validateSecurity(c core.Container, p *core.PodSecurityContext, preparation bool) error {
	s := c.SecurityContext
	if s == nil {
		return fmt.Errorf("%s.securityContext: explicit restricted context required", c.Name)
	}
	uid, gid := s.RunAsUser, s.RunAsGroup
	if p != nil {
		if uid == nil {
			uid = p.RunAsUser
		}
		if gid == nil {
			gid = p.RunAsGroup
		}
	}
	if uid == nil || *uid < 0 || !preparation && (*uid == 0 || gid == nil || *gid <= 0) {
		return fmt.Errorf("%s.securityContext: unsupported workload identity", c.Name)
	}
	if s.Privileged != nil && *s.Privileged || s.AllowPrivilegeEscalation == nil || *s.AllowPrivilegeEscalation || s.Capabilities == nil || !slices.Contains(s.Capabilities.Drop, core.Capability("ALL")) {
		return fmt.Errorf("%s.securityContext: privilege escalation prohibited; drop ALL required", c.Name)
	}
	for _, cap := range s.Capabilities.Add {
		if !preparation || !slices.Contains([]core.Capability{"CHOWN", "FOWNER", "DAC_OVERRIDE"}, cap) {
			return fmt.Errorf("%s.securityContext.capabilities: %s unsupported", c.Name, cap)
		}
	}
	if s.ProcMount != nil && *s.ProcMount != core.DefaultProcMount {
		return fmt.Errorf("%s.securityContext.procMount: unsupported", c.Name)
	}
	for _, port := range c.Ports {
		if port.HostPort != 0 {
			return fmt.Errorf("%s.ports: hostPort unsupported", c.Name)
		}
	}
	return nil
}
