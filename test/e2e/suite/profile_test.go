package suite

import (
	"path/filepath"
	"testing"
)

func TestProfilesKeepTheOriginalInventoryAndRegisterEveryNewCase(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := NewProfileReport(root, t.TempDir(), "istio-only", "baseline", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Cases) != 43 {
		t.Fatalf("legacy inventory changed: %d", len(baseline.Cases))
	}
	candidate, err := NewProfileReport(root, t.TempDir(), "calico-istio", "enforce", "test", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Cases) != 143 {
		t.Fatalf("candidate inventory: got %d want 143", len(candidate.Cases))
	}
	for _, c := range candidate.Cases {
		if c.ID == "N5-01" || c.ID == "N5-02" || c.ID == "C1-04" || c.ID == "C1-05" {
			t.Fatalf("retired allowance in strict inventory: %s", c.ID)
		}
		if c.Actual != NotRun {
			t.Fatalf("unexecuted case already has result: %+v", c)
		}
	}
	if _, err = NewProfileReport(root, t.TempDir(), "calico-istio", "baseline", "test", false); err == nil {
		t.Fatal("candidate baseline exemption allowed")
	}
	if _, err = NewProfileReport(root, t.TempDir(), "unknown", "enforce", "test", false); err == nil {
		t.Fatal("unknown profile allowed")
	}
}
