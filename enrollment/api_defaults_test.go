package enrollment_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/enrollment"
	core "k8s.io/api/core/v1"
)

// The fixture is a real v1.34.11 server-side create dry-run, with volatile
// metadata removed. Token automount is disabled: admission-added mounts are not field defaults.
func TestRealAPIDefaultingRoundTrip(t *testing.T) {
	data, err := os.ReadFile("testdata/api-defaults-1.34.11.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		ServerVersion    string
		Input, Defaulted core.Pod
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.ServerVersion != "v1.34.11" {
		t.Fatal(f.ServerVersion)
	}
	p := &f.Defaulted
	o := enrollment.Options{Network: enrollment.Network{Namespace: p.Namespace, Binding: "example"}, Trusted: enrollment.TrustedSpec{InitContainers: f.Input.Spec.InitContainers, Containers: f.Input.Spec.Containers, Volumes: f.Input.Spec.Volumes}}
	before := p.DeepCopy()
	got, err := enrollment.ExpandPod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p, before) {
		t.Fatal("input mutated")
	}
	again, err := enrollment.ExpandPod(got, o)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("defaulted expansion changed", err)
	}
}
