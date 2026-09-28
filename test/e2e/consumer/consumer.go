// Package consumer is the static E2E caller, not a public proxy injector.
package consumer

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Network(namespace string) (enrollment.Network, string, error) {
	n := enrollment.Network{Namespace: namespace, Binding: "np", Forward: []enrollment.TCPDestination{{Peer: enrollment.Peer{Namespace: "networking-np", PodLabels: map[string]string{"app": "httpbin"}}, Ports: []int32{8080}}}}
	if namespace != "networking-np" {
		return n, "", fmt.Errorf("unsupported fixture namespace %s", namespace)
	}
	return n, "httpbin-only", nil
}

// RenderPolicy is called before creating the protected workload.
func RenderPolicy(out io.Writer, namespace string) error {
	n, name, err := Network(namespace)
	if err != nil {
		return err
	}
	p, err := enrollment.ExpandPolicy(n)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(&network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: namespace}, Spec: p.Spec})
}

func RenderPod(in io.Reader, out io.Writer) error {
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
	n, _, err := Network(pod.Namespace)
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

	if pod.Spec.ServiceAccountName == "" {
		pod.Spec.ServiceAccountName = "default"
	}
	for _, group := range [][]core.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for i := range group {
			if group[i].SecurityContext != nil && group[i].SecurityContext.RunAsGroup == nil {
				group[i].SecurityContext.RunAsGroup = new(int64(10000))
			}
		}
	}
	v, err := enrollment.ExpandPod(&pod, enrollment.Options{Network: n})
	if err != nil {
		return err
	}
	pod = *v

	if kind.Kind == "Deployment" {
		pod.Namespace = ""
		deployment.Spec.Template = core.PodTemplateSpec{ObjectMeta: pod.ObjectMeta, Spec: pod.Spec}
		return json.NewEncoder(out).Encode(deployment)
	}
	return json.NewEncoder(out).Encode(pod)
}
