// Package consumer is the static E2E caller, not a public proxy injector.
package consumer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/egress-gateway/egress-gateway-networking/baseline"
	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const EnabledLabel = "networking.egress/enabled"

func Network(namespace, controlIP string) (enrollment.Network, string, error) {
	n := enrollment.Network{Namespace: namespace, Binding: "egress"}
	name := "protected-egress"
	switch {
	case namespace == "networking-np":
		n.Binding = "np"
		name = "httpbin-only"
		n.Forward = []enrollment.TCPDestination{{Peer: enrollment.Peer{Namespace: namespace, PodLabels: map[string]string{"app": "httpbin"}}, Ports: []int32{8080}}}
		return n, name, nil
	case strings.HasPrefix(namespace, "networking-dns"):
		n.Binding = "dns"
		name = "local-dns-egress"
		n.Forward = []enrollment.TCPDestination{{Peer: enrollment.Peer{Namespace: namespace, PodLabels: map[string]string{"app": "receiver"}}, Ports: []int32{8080, 8443, 9000}}}
	case namespace == "networking-egress":
		n.Forward = []enrollment.TCPDestination{{Peer: enrollment.Peer{Namespace: "networking-gateway", PodLabels: map[string]string{"app": "gateway"}}, Ports: []int32{15443, 15444}}}
	default:
		return n, "", fmt.Errorf("unknown fixture namespace %q", namespace)
	}
	n.Control = &enrollment.Istiod{IPv4: controlIP, Hostname: "istiod.istio-system.svc", Peer: enrollment.Peer{Namespace: "istio-system", PodLabels: map[string]string{"app": "istiod"}}}
	return n, name, nil
}

// RenderPolicy is called before creating the protected workload.
func RenderPolicy(out io.Writer, namespace, ip string) error {
	n, name, err := Network(namespace, ip)
	if err != nil {
		return err
	}
	p, err := enrollment.ExpandPolicy(n)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(&network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: p.Spec})
}

// Runtime is a consumer-supplied fragment. Network-owned fields still pass the
// public validator; this interface cannot disable validation or policy generation.
type Runtime struct {
	Proxy       core.Container   `json:"proxy"`
	Init        []core.Container `json:"init,omitempty"`
	Volumes     []core.Volume    `json:"volumes,omitempty"`
	TrustedInit []string         `json:"trustedInit,omitempty"`
}

func RenderPod(in io.Reader, out io.Writer, ip, proxyFile string, policyOnly bool) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return err
	}
	var kind meta.TypeMeta
	if err = json.Unmarshal(data, &kind); err != nil {
		return err
	}
	var pod core.Pod
	var deployment apps.Deployment
	if kind.Kind == "Deployment" {
		if err = json.Unmarshal(data, &deployment); err != nil {
			return err
		}
		pod = core.Pod{ObjectMeta: deployment.Spec.Template.ObjectMeta, Spec: deployment.Spec.Template.Spec}
		pod.Namespace = deployment.Namespace
	} else if kind.Kind == "Pod" {
		if err = json.Unmarshal(data, &pod); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("expected Pod or Deployment")
	}
	n, _, err := Network(pod.Namespace, ip)
	if err != nil {
		return err
	}
	policy, err := enrollment.ExpandPolicy(n)
	if err != nil {
		return err
	}
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	for k, v := range policy.Labels {
		pod.Labels[k] = v
	}
	if !policyOnly {
		// These templates predate the public manual path; translate only here in
		// the static caller. Public expansion itself rejects injector overrides.
		delete(pod.Annotations, "sidecar.istio.io/inject")
		delete(pod.Annotations, "proxy.istio.io/config")
		pod.Labels[EnabledLabel] = "true"
		if pod.Spec.ServiceAccountName == "" {
			pod.Spec.ServiceAccountName = "client"
		}
		for i := range pod.Spec.Containers {
			c := &pod.Spec.Containers[i]
			if c.SecurityContext != nil && c.SecurityContext.RunAsGroup == nil {
				c.SecurityContext.RunAsGroup = new(int64(10000))
			}
		}
		r := OfficialRuntime()
		if proxyFile != "" {
			r = Runtime{}
			data, err := os.ReadFile(proxyFile)
			if err != nil {
				return err
			}
			if err = json.Unmarshal(data, &r); err != nil {
				return err
			}
		}
		pod.Spec.InitContainers = append(append(r.Init, r.Proxy), pod.Spec.InitContainers...)
		pod.Spec.Volumes = append(pod.Spec.Volumes, r.Volumes...)
		v, err := enrollment.ExpandPod(&pod, enrollment.Options{Network: n, EnabledLabel: EnabledLabel, TrustedInit: r.TrustedInit})
		if err != nil {
			return err
		}
		pod = *v
	}
	if kind.Kind == "Deployment" {
		pod.Namespace = ""
		deployment.Spec.Template = core.PodTemplateSpec{ObjectMeta: pod.ObjectMeta, Spec: pod.Spec}
		return json.NewEncoder(out).Encode(deployment)
	}
	return json.NewEncoder(out).Encode(pod)
}

func OfficialRuntime() Runtime {
	field := func(name, path string) core.EnvVar {
		return core.EnvVar{Name: name, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: path}}}
	}
	p := core.Container{Name: enrollment.ProxyName, Image: baseline.Current().Runtime["ISTIO_PROXY_IMAGE"], ImagePullPolicy: core.PullIfNotPresent,
		Args: []string{"proxy", "sidecar", "--domain", "$(POD_NAMESPACE).svc.cluster.local", "--proxyLogLevel=warning"}, RestartPolicy: new(core.ContainerRestartPolicyAlways),
		SecurityContext: &core.SecurityContext{RunAsUser: new(int64(1337)), RunAsGroup: new(int64(1337)), RunAsNonRoot: new(true), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
		StartupProbe:    &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: &core.HTTPGetAction{Path: "/healthz/ready", Port: intstr.FromInt32(15021)}}, PeriodSeconds: 1, FailureThreshold: 90, TimeoutSeconds: 1},
		ReadinessProbe:  &core.Probe{ProbeHandler: core.ProbeHandler{HTTPGet: &core.HTTPGetAction{Path: "/healthz/ready", Port: intstr.FromInt32(15021)}}, PeriodSeconds: 2, FailureThreshold: 3, TimeoutSeconds: 1},
		Env:             []core.EnvVar{field("POD_NAME", "metadata.name"), field("POD_NAMESPACE", "metadata.namespace"), field("INSTANCE_IP", "status.podIP"), field("SERVICE_ACCOUNT", "spec.serviceAccountName"), {Name: "JWT_POLICY", Value: "third-party-jwt"}, {Name: "ISTIO_META_CLUSTER_ID", Value: "Kubernetes"}, {Name: "ISTIO_META_MESH_ID", Value: "cluster.local"}, {Name: "TRUST_DOMAIN", Value: "cluster.local"}, {Name: "PROXY_CONFIG", Value: `{"concurrency":2}`}},
		VolumeMounts:    []core.VolumeMount{{Name: "enrollment-data", MountPath: "/etc/istio/proxy"}, {Name: "enrollment-socket", MountPath: "/var/run/secrets/workload-spiffe-uds"}, {Name: "enrollment-credentials", MountPath: "/var/run/secrets/credential-uds"}, {Name: "enrollment-certs", MountPath: "/var/run/secrets/workload-spiffe-credentials"}, {Name: "enrollment-token", MountPath: "/var/run/secrets/tokens", ReadOnly: true}, {Name: "enrollment-ca", MountPath: "/var/run/secrets/istio", ReadOnly: true}},
	}
	r := Runtime{Proxy: p, TrustedInit: []string{"prepare-proxy-volumes"}}
	r.Init = []core.Container{{Name: "prepare-proxy-volumes", Image: p.Image, ImagePullPolicy: core.PullIfNotPresent, Command: []string{"/bin/sh", "-c", "chown 1337:1337 /etc/istio/proxy /var/run/secrets/workload-spiffe-uds /var/run/secrets/credential-uds /var/run/secrets/workload-spiffe-credentials && chmod 0700 /etc/istio/proxy /var/run/secrets/workload-spiffe-uds /var/run/secrets/credential-uds /var/run/secrets/workload-spiffe-credentials"}, VolumeMounts: append([]core.VolumeMount{}, p.VolumeMounts[:4]...), SecurityContext: &core.SecurityContext{RunAsUser: new(int64(0)), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}, Add: []core.Capability{"CHOWN", "FOWNER"}}}}}
	for _, name := range []string{"enrollment-data", "enrollment-socket", "enrollment-credentials", "enrollment-certs"} {
		r.Volumes = append(r.Volumes, core.Volume{Name: name, VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}})
	}
	r.Volumes = append(r.Volumes,
		core.Volume{Name: "enrollment-token", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: "istio-ca", ExpirationSeconds: new(int64(43200)), Path: "istio-token"}}}}}},
		core.Volume{Name: "enrollment-ca", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: "istio-ca-root-cert"}}}})
	return r
}
