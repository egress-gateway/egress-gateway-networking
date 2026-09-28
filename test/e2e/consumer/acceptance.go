package consumer

import (
	"encoding/json"
	"io"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RenderAcceptance is the static consumer for independent bindings.
func RenderAcceptance(out io.Writer, image string) error {
	var objects []any
	objects = append(objects, &core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "networking-enrollment"}})
	for _, binding := range []string{"a", "b", "trusted"} {
		app := "httpbin"
		if binding == "b" {
			app = "other"
		}
		n := enrollment.Network{Namespace: "networking-enrollment", Binding: binding, Forward: []enrollment.TCPDestination{{Peer: enrollment.Peer{Namespace: "networking-np", PodLabels: map[string]string{"app": app}}, Ports: []int32{8080}}}}
		p, err := enrollment.ExpandPolicy(n)
		if err != nil {
			return err
		}
		objects = append(objects, &network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: binding, Namespace: n.Namespace}, Spec: p.Spec})
		pod := &core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: binding, Namespace: n.Namespace, Labels: p.Labels}, Spec: core.PodSpec{ServiceAccountName: "default", AutomountServiceAccountToken: new(false), Containers: []core.Container{{Name: "probe", Image: image, ImagePullPolicy: core.PullNever, Args: []string{"idle"}, SecurityContext: &core.SecurityContext{RunAsUser: new(int64(10000)), RunAsGroup: new(int64(10000)), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}

		options := enrollment.Options{Network: n}
		if binding == "trusted" {
			prep := core.Container{Name: "prepare-files", Image: image, ImagePullPolicy: core.PullNever, Args: []string{"prepare"}, VolumeMounts: []core.VolumeMount{{Name: "private", MountPath: "/private"}}, SecurityContext: &core.SecurityContext{RunAsUser: new(int64(0)), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}, Add: []core.Capability{"CHOWN", "FOWNER"}}}}
			resident := core.Container{Name: "runtime", Image: image, ImagePullPolicy: core.PullNever, Args: []string{"private-idle"}, RestartPolicy: new(core.ContainerRestartPolicyAlways), VolumeMounts: []core.VolumeMount{{Name: "private", MountPath: "/private"}}, SecurityContext: &core.SecurityContext{RunAsUser: new(int64(2000)), RunAsGroup: new(int64(2000)), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}
			volume := core.Volume{Name: "private", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}}
			options.Trusted = enrollment.TrustedSpec{InitContainers: []core.Container{*prep.DeepCopy(), *resident.DeepCopy()}, Volumes: []core.Volume{*volume.DeepCopy()}}
			pod.Spec.InitContainers = []core.Container{prep, resident}
			pod.Spec.Volumes = []core.Volume{volume}
		}
		expanded, err := enrollment.ExpandPod(pod, options)
		if err != nil {
			return err
		}
		objects = append(objects, expanded)

	}
	return json.NewEncoder(out).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "items": objects})
}

func RenderResolverPolicy(out io.Writer, namespace, resolver string) error {
	n, name, err := Network(namespace)
	if err != nil {
		return err
	}
	if resolver != "" {
		n.DNS = []enrollment.Peer{{IPv4: resolver}}
	}
	p, err := enrollment.ExpandPolicy(n)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(&network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: p.Spec})
}
