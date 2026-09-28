// The platform owns these inputs. This example emits objects; it does not write
// to a cluster. Apply the policy before creating the checked workload.
package main

import (
	"encoding/json"
	"os"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func main() {
	security := func(id int64) *core.SecurityContext {
		return &core.SecurityContext{RunAsUser: new(id), RunAsGroup: new(id), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}
	}
	image := "docker.io/library/busybox:1.36.1"
	volume := core.Volume{Name: "runtime-private", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}}
	prep := core.Container{Name: "prepare", Image: image, Command: []string{"sh", "-c", "chown 2000:2000 /private && chmod 0700 /private"}, SecurityContext: security(0), VolumeMounts: []core.VolumeMount{{Name: volume.Name, MountPath: "/private"}}}
	prep.SecurityContext.Capabilities.Add = []core.Capability{"CHOWN", "FOWNER"}
	resident := core.Container{Name: "runtime", Image: image, Command: []string{"sleep", "3600"}, SecurityContext: security(2000), VolumeMounts: []core.VolumeMount{{Name: volume.Name, MountPath: "/private"}}}
	trusted := enrollment.TrustedSpec{InitContainers: []core.Container{*prep.DeepCopy()}, Containers: []core.Container{*resident.DeepCopy()}, Volumes: []core.Volume{*volume.DeepCopy()}}
	n := enrollment.Network{Namespace: "tenant", Binding: "example", Forward: []enrollment.TCPDestination{{Peer: enrollment.Peer{Namespace: "gateway", PodLabels: map[string]string{"app": "gateway"}}, Ports: []int32{15443}}}}
	p := &core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: "example", Namespace: n.Namespace}, Spec: core.PodSpec{ServiceAccountName: "default", AutomountServiceAccountToken: new(false), InitContainers: []core.Container{prep}, Containers: []core.Container{{Name: "business", Image: image, Command: []string{"sleep", "3600"}, SecurityContext: security(10000)}, resident}, Volumes: []core.Volume{volume}}}
	policy, err := enrollment.ExpandPolicy(n)
	if err != nil {
		panic(err)
	}
	pod, err := enrollment.ExpandPod(p, enrollment.Options{Network: n, Trusted: trusted})
	if err != nil {
		panic(err)
	}
	bad := p.DeepCopy()
	bad.Spec.InitContainers[0].Command = []string{"untrusted"}
	if _, err = enrollment.ExpandPod(bad, enrollment.Options{Network: n, Trusted: trusted}); err == nil {
		panic("unsafe substitution accepted")
	}
	np := &network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "example", Namespace: n.Namespace}, Spec: policy.Spec}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"apiVersion": "v1", "kind": "List", "items": []any{np, pod}}); err != nil {
		panic(err)
	}
}
