package enrollment

import (
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/egress-gateway/egress-gateway-networking/baseline"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const ProxyName = "istio-proxy"
const ProxyID int64 = 1337

// Options contains installation/caller facts, never template overrides.
type Options struct {
	Network Network `json:"network"`
	// EnabledLabel must already be true on the submitted Pod and must match the
	// installed neverInjectSelector before controller admission runs.
	EnabledLabel string `json:"enabledLabel"`
	// TrustedInit names bounded, short-lived local preparation containers placed
	// before the proxy. It does not exempt capabilities or namespace restrictions.
	TrustedInit []string `json:"trustedInit,omitempty"`
}

// ExpandPod returns a copy. A nil result on any error prevents partial adoption.
func ExpandPod(input *core.Pod, o Options) (*core.Pod, error) {
	if input == nil {
		return nil, fmt.Errorf("pod: required")
	}
	policy, err := ExpandPolicy(o.Network)
	if err != nil {
		return nil, err
	}
	if o.Network.Control == nil {
		return nil, fmt.Errorf("network.control: required for full enrollment")
	}
	if input.Namespace != o.Network.Namespace {
		return nil, fmt.Errorf("metadata.namespace: must match network namespace")
	}
	if input.Spec.ServiceAccountName == "" || len(validation.IsDNS1123Subdomain(input.Spec.ServiceAccountName)) != 0 {
		return nil, fmt.Errorf("spec.serviceAccountName: explicit valid identity required")
	}
	if len(validation.IsQualifiedName(o.EnabledLabel)) != 0 || strings.HasSuffix(o.EnabledLabel, "istio.io/inject") || o.EnabledLabel == BindingLabel || input.Labels[o.EnabledLabel] != "true" {
		return nil, fmt.Errorf("enabledLabel: valid original enabled=true label required")
	}
	p := input.DeepCopy()
	if p.Labels == nil {
		p.Labels = map[string]string{}
	}
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC || (p.Spec.ShareProcessNamespace != nil && *p.Spec.ShareProcessNamespace) {
		return nil, fmt.Errorf("spec: shared host/process namespaces are unsupported")
	}
	if len(p.Spec.EphemeralContainers) != 0 {
		return nil, fmt.Errorf("spec.ephemeralContainers: unsupported")
	}
	if p.Spec.SecurityContext != nil {
		s := p.Spec.SecurityContext
		if s.RunAsUser != nil && (*s.RunAsUser == 0 || *s.RunAsUser == ProxyID) {
			return nil, fmt.Errorf("spec.securityContext.runAsUser: application must not inherit root/proxy identity")
		}
		if s.RunAsGroup != nil && (*s.RunAsGroup == 0 || *s.RunAsGroup == ProxyID) || s.FSGroup != nil && (*s.FSGroup == 0 || *s.FSGroup == ProxyID) || slices.Contains(s.SupplementalGroups, ProxyID) || slices.Contains(s.SupplementalGroups, int64(0)) {
			return nil, fmt.Errorf("spec.securityContext: application must not inherit root/proxy group")
		}
		if len(s.Sysctls) != 0 {
			return nil, fmt.Errorf("spec.securityContext.sysctls: unsupported capture override")
		}
	}
	for _, v := range p.Spec.Volumes {
		if v.HostPath != nil {
			return nil, fmt.Errorf("spec.volumes[%s]: hostPath unsupported", v.Name)
		}
	}
	for k, v := range policy.Labels {
		if err = setFixed(p.Labels, k, v); err != nil {
			return nil, err
		}
	}
	for _, m := range []map[string]string{p.Labels, p.Annotations} {
		if _, ok := m["sidecar.istio.io/inject"]; ok {
			return nil, fmt.Errorf("sidecar.istio.io/inject: omit; installed original-label selector excludes injection without disabling CNI")
		}
		if _, ok := m["istio.io/rev"]; ok {
			return nil, fmt.Errorf("istio.io/rev: consumer-selected injection revision unsupported")
		}
	}
	fixed := map[string]string{
		"traffic.sidecar.istio.io/includeOutboundIPRanges": "*",
		"traffic.sidecar.istio.io/excludeOutboundIPRanges": "",
		"traffic.sidecar.istio.io/includeOutboundPorts":    "",
		"traffic.sidecar.istio.io/excludeOutboundPorts":    "",
		"traffic.sidecar.istio.io/includeInboundPorts":     "",
		"traffic.sidecar.istio.io/excludeInboundPorts":     "15020,15021,15090",
		"sidecar.istio.io/interceptionMode":                "REDIRECT",
	}
	for k := range p.Annotations {
		if strings.HasPrefix(k, "traffic.sidecar.istio.io/") || strings.HasPrefix(k, "sidecar.istio.io/") || strings.HasPrefix(k, "inject.istio.io/") || k == "istio.io/reroute-virtual-interfaces" || k == "status.sidecar.istio.io/port" {
			if _, ok := fixed[k]; !ok && k != "sidecar.istio.io/status" {
				return nil, fmt.Errorf("metadata.annotations[%s]: reserved network field", k)
			}
		}
	}
	for k, v := range fixed {
		if err = setFixed(p.Annotations, k, v); err != nil {
			return nil, err
		}
	}
	// Injector ProxyConfig is not a second input channel in the manual path.
	if _, ok := p.Annotations["proxy.istio.io/config"]; ok {
		return nil, fmt.Errorf("proxy.istio.io/config: injector configuration unsupported in manual path; supply runtime configuration on proxy")
	}
	names := map[string]bool{}
	proxyIndex := -1
	for i, c := range p.Spec.InitContainers {
		if names[c.Name] {
			return nil, fmt.Errorf("initContainers: duplicate %s", c.Name)
		}
		names[c.Name] = true
		if c.Name == "istio-init" {
			return nil, fmt.Errorf("istio-init: CNI owns rule programming")
		}
		if c.Name == ProxyName {
			proxyIndex = i
		}
	}
	for _, c := range p.Spec.Containers {
		if names[c.Name] || c.Name == ProxyName {
			return nil, fmt.Errorf("containers[%s]: duplicate or non-native proxy", c.Name)
		}
		names[c.Name] = true
	}
	if proxyIndex < 0 {
		return nil, fmt.Errorf("initContainers: caller-declared istio-proxy required")
	}
	proxy := &p.Spec.InitContainers[proxyIndex]
	if proxy.RestartPolicy == nil || *proxy.RestartPolicy != core.ContainerRestartPolicyAlways || proxy.StartupProbe == nil || proxy.ReadinessProbe == nil {
		return nil, fmt.Errorf("istio-proxy: native restartPolicy and explicit startup/readiness probes required")
	}
	if proxy.Image == "" {
		return nil, fmt.Errorf("istio-proxy.image: required")
	}
	if err = validateSecurity(proxy, p.Spec.SecurityContext, true, false); err != nil {
		return nil, err
	}
	control := o.Network.Control
	fixedEnvironment := map[string]string{"ISTIO_META_DNS_CAPTURE": "true", "ISTIO_META_INTERCEPTION_MODE": "REDIRECT", "DISABLE_ENVOY": "false", "ISTIO_DUAL_STACK": "false", "CA_ADDR": control.Hostname + ":15012", "PILOT_CERT_PROVIDER": "istiod", "DNS_PROXY_ADDR": "localhost:15053", "ISTIOD_SAN": control.Hostname}
	for _, k := range slices.Sorted(maps.Keys(fixedEnvironment)) {
		v := fixedEnvironment[k]
		if err = fixedEnv(proxy, k, v); err != nil {
			return nil, err
		}
	}
	if err = proxyConfig(proxy, control.Hostname); err != nil {
		return nil, err
	}
	trusted := map[string]bool{}
	for _, name := range o.TrustedInit {
		if trusted[name] || name == ProxyName || name == "istio-validation" || !names[name] {
			return nil, fmt.Errorf("trustedInit: invalid/duplicate container %q", name)
		}
		trusted[name] = true
	}
	for i := range p.Spec.InitContainers {
		c := &p.Spec.InitContainers[i]
		if c.Name == ProxyName || c.Name == "istio-validation" {
			continue
		}
		if trusted[c.Name] {
			if i > proxyIndex || c.RestartPolicy != nil {
				return nil, fmt.Errorf("trustedInit[%s]: must be a terminating preparation before proxy", c.Name)
			}
			delete(trusted, c.Name)
		} else if i < proxyIndex {
			return nil, fmt.Errorf("initContainers[%s]: business init cannot precede proxy startup", c.Name)
		}
		if err = validateSecurity(c, p.Spec.SecurityContext, false, slices.Contains(o.TrustedInit, c.Name)); err != nil {
			return nil, err
		}
	}
	if len(trusted) != 0 {
		return nil, fmt.Errorf("trustedInit: only initialization containers may be designated")
	}
	for i := range p.Spec.Containers {
		if err = validateSecurity(&p.Spec.Containers[i], p.Spec.SecurityContext, false, false); err != nil {
			return nil, err
		}
	}
	validation := validationContainer()
	idx := slices.IndexFunc(p.Spec.InitContainers, func(c core.Container) bool { return c.Name == validation.Name })
	if idx >= 0 {
		if idx != 0 || !reflect.DeepEqual(p.Spec.InitContainers[idx], validation) {
			return nil, fmt.Errorf("istio-validation: fixed first initialization contract conflicts")
		}
	} else {
		p.Spec.InitContainers = slices.Insert(p.Spec.InitContainers, 0, validation)
	}
	status, _ := json.Marshal(map[string]any{"initContainers": []string{"istio-validation", ProxyName}, "containers": []string{}, "volumes": []string{}, "imagePullSecrets": []string{}, "revision": "default"})
	if err = setFixed(p.Annotations, "sidecar.istio.io/status", string(status)); err != nil {
		return nil, err
	}
	found := false
	for _, a := range p.Spec.HostAliases {
		for _, host := range a.Hostnames {
			if host == control.Hostname {
				if a.IP != control.IPv4 {
					return nil, fmt.Errorf("hostAliases: conflicting Istiod address")
				}
				found = true
			}
		}
	}
	if !found {
		p.Spec.HostAliases = append(p.Spec.HostAliases, core.HostAlias{IP: control.IPv4, Hostnames: []string{control.Hostname}})
	}
	return p, nil
}

func setFixed(m map[string]string, k, v string) error {
	if old, ok := m[k]; ok && old != v {
		return fmt.Errorf("%s: conflicts with fixed network contract", k)
	}
	m[k] = v
	return nil
}

func fixedEnv(c *core.Container, k, v string) error {
	seen := false
	for _, e := range c.Env {
		if e.Name == k {
			if seen || e.ValueFrom != nil || e.Value != v {
				return fmt.Errorf("%s.env[%s]: conflicts with fixed network contract", c.Name, k)
			}
			seen = true
		}
	}
	if !seen {
		c.Env = append(c.Env, core.EnvVar{Name: k, Value: v})
	}
	return nil
}

func proxyConfig(c *core.Container, host string) error {
	if len(c.EnvFrom) != 0 {
		return fmt.Errorf("istio-proxy.envFrom: cannot verify network values")
	}
	var config = map[string]any{}
	index := -1
	for i, e := range c.Env {
		if e.Name == "PROXY_CONFIG" {
			if index >= 0 || e.ValueFrom != nil {
				return fmt.Errorf("PROXY_CONFIG: unique literal JSON required")
			}
			index = i
			if err := json.Unmarshal([]byte(e.Value), &config); err != nil || config == nil {
				return fmt.Errorf("PROXY_CONFIG: JSON object required")
			}
		}
		if (strings.HasPrefix(e.Name, "ISTIO_META_") && slices.Contains([]string{"ISTIO_META_DNS_AUTO_ALLOCATE", "ISTIO_META_ENABLE_HBONE", "ISTIO_META_DNS_PROXY_ADDR"}, e.Name)) || e.Name == "ISTIO_ENVOY_PORT" {
			return fmt.Errorf("istio-proxy.env[%s]: unsupported network override", e.Name)
		}
	}
	fixed := map[string]any{"discoveryAddress": host + ":15012", "proxyAdminPort": float64(15000), "interceptionMode": "REDIRECT", "controlPlaneAuthPolicy": "MUTUAL_TLS", "statusPort": float64(15020)}
	for k, v := range fixed {
		if old, ok := config[k]; ok && !reflect.DeepEqual(old, v) {
			return fmt.Errorf("PROXY_CONFIG.%s: conflicts with network contract", k)
		}
		config[k] = v
	}
	metadata := map[string]any{}
	if raw, ok := config["proxyMetadata"]; ok {
		var valid bool
		metadata, valid = raw.(map[string]any)
		if !valid {
			return fmt.Errorf("PROXY_CONFIG.proxyMetadata: object required")
		}
		metadata = maps.Clone(metadata)
	}
	for k, v := range map[string]string{"ISTIO_META_DNS_CAPTURE": "true", "ISTIO_META_INTERCEPTION_MODE": "REDIRECT", "DISABLE_ENVOY": "false", "ISTIO_DUAL_STACK": "false"} {
		if old, ok := metadata[k]; ok && old != v {
			return fmt.Errorf("PROXY_CONFIG.proxyMetadata.%s: conflicting network value", k)
		}
		metadata[k] = v
	}
	config["proxyMetadata"] = metadata
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	e := core.EnvVar{Name: "PROXY_CONFIG", Value: string(data)}
	if index < 0 {
		c.Env = append(c.Env, e)
	} else {
		c.Env[index] = e
	}
	return nil
}

func validateSecurity(c *core.Container, p *core.PodSecurityContext, proxy, preparation bool) error {
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
	if uid == nil || *uid < 0 || proxy && (*uid != ProxyID || gid == nil || *gid != ProxyID) || !proxy && !preparation && (*uid == 0 || *uid == ProxyID || (gid == nil || *gid <= 0 || *gid == ProxyID)) {
		return fmt.Errorf("%s.securityContext: unsupported application/proxy identity", c.Name)
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
	if s.SeccompProfile != nil && s.SeccompProfile.Type == core.SeccompProfileTypeUnconfined {
		return fmt.Errorf("%s.securityContext.seccompProfile: unconfined unsupported", c.Name)
	}
	for _, p := range c.Ports {
		if p.HostPort != 0 {
			return fmt.Errorf("%s.ports: hostPort unsupported", c.Name)
		}
	}
	return nil
}

func validationContainer() core.Container {
	return core.Container{Name: "istio-validation", Image: baseline.Current().Runtime["ISTIO_PROXY_IMAGE"], ImagePullPolicy: core.PullIfNotPresent,
		Args:            []string{"istio-iptables", "-p", "15001", "-z", "15006", "-u", "1337", "-m", "REDIRECT", "-i", "*", "-x", "", "-b", "", "-d", "15020,15021,15090", "--run-validation", "--skip-rule-apply"},
		Env:             []core.EnvVar{{Name: "ISTIO_META_DNS_CAPTURE", Value: "true"}},
		SecurityContext: &core.SecurityContext{RunAsUser: new(ProxyID), RunAsGroup: new(ProxyID), RunAsNonRoot: new(true), AllowPrivilegeEscalation: new(false), ReadOnlyRootFilesystem: new(true), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}
}
