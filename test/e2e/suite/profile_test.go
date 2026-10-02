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
	for _, id := range []string{"NP-01", "NP-08", "C3-03", "C3-04", "C4-03", "E1-04", "N1-20-TCP", "N1-21-TCP", "C3-03-TCP", "C3-04-TCP", "N1-23", "N1-24", "N1-25", "N1-26", "N1-22", "N1-27", "A1-01", "A1-02", "A1-03", "A1-04", "A1-05", "A1-06", "A1-07", "A1-08"} {
		if !seen[id] {
			t.Fatalf("missing required case %s", id)
		}
	}
}
