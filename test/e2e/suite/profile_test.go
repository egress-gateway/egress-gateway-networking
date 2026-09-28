package suite

import (
	"path/filepath"
	"testing"
)

func TestOnlyCalicoEnforceInventory(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"istio-only", "baseline"}, {"calico-istio", "enforce"}, {"calico", "baseline"}, {"unknown", "enforce"}} {
		if _, err := NewProfileReport(root, t.TempDir(), pair[0], pair[1], "test", false); err == nil {
			t.Fatalf("legacy/unknown mode accepted: %v", pair)
		}
	}
	r, err := NewProfileReport(root, t.TempDir(), "calico", "enforce", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range r.Cases {
		seen[c.ID] = true
		if c.Actual != NotRun {
			t.Fatalf("unexecuted result: %+v", c)
		}
	}
	for _, id := range []string{"NP-01", "NP-08", "C3-03", "C3-04", "C4-03", "E1-04"} {
		if !seen[id] {
			t.Fatalf("missing required case %s", id)
		}
	}
}
