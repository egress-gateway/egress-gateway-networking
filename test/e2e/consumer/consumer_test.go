package consumer

import (
	"bytes"
	"encoding/json"
	core "k8s.io/api/core/v1"
	"testing"
)

func TestStaticConsumerBindsWithoutInjecting(t *testing.T) {
	input := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"networking-np","name":"consumer"},"spec":{"containers":[{"name":"probe","image":"test","securityContext":{"runAsUser":10000,"runAsNonRoot":true,"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}`)
	var out bytes.Buffer
	if err := RenderPod(bytes.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	var p core.Pod
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Spec.InitContainers) != 0 || len(p.Spec.Containers) != 1 || len(p.Labels) == 0 {
		t.Fatalf("unexpected expansion: %+v", p)
	}
}
