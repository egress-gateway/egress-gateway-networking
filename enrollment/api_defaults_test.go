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
		ServerVersion              string
		Input, Expanded, Defaulted core.Pod
		Options                    enrollment.Options
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.ServerVersion != "v1.34.11" {
		t.Fatalf("unexpected server %s", f.ServerVersion)
	}
	generated, err := enrollment.ExpandPod(&f.Input, f.Options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(generated, &f.Expanded) {
		t.Fatal("valid pre-API output changed")
	}
	before := f.Defaulted.DeepCopy()
	result, err := enrollment.ExpandPod(&f.Defaulted, f.Options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, before) || !reflect.DeepEqual(&f.Defaulted, before) {
		t.Fatal("defaulted caller object changed")
	}
	if len(result.Spec.InitContainers) != 4 || result.Spec.InitContainers[0].Name != "istio-validation" {
		t.Fatal("startup order changed")
	}
}

func TestAPIAppArmorAnnotationConversion(t *testing.T) {
	data, err := os.ReadFile("testdata/api-defaults-1.34.11.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Options         enrollment.Options
		LegacyDefaulted core.Pod
	}
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	before := f.LegacyDefaulted.DeepCopy()
	result, err := enrollment.ExpandPod(&f.LegacyDefaulted, f.Options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, before) || !reflect.DeepEqual(&f.LegacyDefaulted, before) {
		t.Fatal("AppArmor conversion changed caller object")
	}
	f.LegacyDefaulted.Spec.InitContainers[0].SecurityContext.AppArmorProfile = &core.AppArmorProfile{Type: core.AppArmorProfileTypeUnconfined}
	result, err = enrollment.ExpandPod(&f.LegacyDefaulted, f.Options)
	if err == nil || result != nil {
		t.Fatal("conflicting materialized AppArmor accepted")
	}
}
