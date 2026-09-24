package suite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestIstioProfileExcludesCalicoFromEveryGodogORBranch(t *testing.T) {
	dir := t.TempDir()
	features := filepath.Join(dir, "test/e2e/features")
	if err := os.MkdirAll(features, 0700); err != nil {
		t.Fatal(err)
	}
	feature := `Feature: Profile selection
  @a
  Scenario: A selected first branch
    Given the shared Istio installation and test workloads are ready
  @b
  Scenario: B selected second branch
    Given the shared Istio installation and test workloads are ready
  @calico @a
  Scenario: C excluded first branch
    Given the shared Istio installation and test workloads are ready
  @calico @b
  Scenario: D excluded second branch
    Given the shared Istio installation and test workloads are ready
`
	for file, data := range map[string]string{filepath.Join(features, "selection.feature"): feature, filepath.Join(dir, "environment.json"): `{"inputs":"test"}`} {
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	report := &Report{Profile: "istio-only", Mode: "enforce", Dir: dir, Cases: []CaseResult{{ID: "A", Actual: NotRun}, {ID: "B", Actual: NotRun}}}
	s := Suite{Root: dir, State: dir, Artifacts: dir, Tags: "@a,@b", Report: report}
	if err := s.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range report.Cases {
		if c.Actual != Satisfied {
			t.Fatalf("case %s: %s", c.ID, c.Actual)
		}
	}
}
