package consumer

import (
	"bytes"
	"encoding/json"
	"testing"

	core "k8s.io/api/core/v1"
)

func TestStaticConsumerExpandsNativeSidecarAndPolicy(t *testing.T) {
	input := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"networking-egress","name":"consumer"},"spec":{"containers":[{"name":"probe","image":"test","securityContext":{"runAsUser":10000,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}`)
	var out bytes.Buffer
	if err := RenderPod(bytes.NewReader(input), &out, "10.96.0.12", "", false); err != nil {
		t.Fatal(err)
	}
	var p core.Pod
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.InitContainers) != 3 || p.Spec.InitContainers[0].Name != "istio-validation" || p.Spec.InitContainers[1].Name != "prepare-proxy-volumes" || p.Spec.InitContainers[2].Name != "istio-proxy" {
		t.Fatal("incorrect native initialization order")
	}
	if p.Spec.HostAliases[0].IP != "10.96.0.12" || p.Labels[EnabledLabel] != "true" {
		t.Fatal("missing bootstrap/original enabled selector")
	}
	if _, ok := p.Annotations["sidecar.istio.io/inject"]; ok {
		t.Fatal("explicit injection override disables CNI")
	}
	out.Reset()
	if err := RenderPod(bytes.NewReader(input), &out, "10.96.0.12", "", true); err != nil {
		t.Fatal(err)
	}
	p = core.Pod{}
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.InitContainers) != 0 || len(p.Spec.HostAliases) != 0 || p.Labels[EnabledLabel] != "" {
		t.Fatal("policy-only consumer acquired sidecar/bootstrap")
	}
}
