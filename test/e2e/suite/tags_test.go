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

func TestGroupedFailureRecordsAllSelectedCases(t *testing.T) {
	for _, failID := range []string{"N1-01", "D1-01"} {
		t.Run(failID, func(t *testing.T) {
			s := completionFixture(t)
			for i := range s.Report.Cases {
				if s.Report.Cases[i].ID == failID {
					s.Report.Cases[i].FunctionalityRequired = true
				}
			}
			// The missing required functionality gives a real nonzero Godog result.
			// It must remain an acceptance failure, not suppress another selected group.
			if err := s.Run(t.Context()); err != nil {
				t.Fatal(err)
			}
			for _, c := range s.Report.Results() {
				if c.ID == "OTHER" {
					if c.Actual != NotRun {
						t.Fatal("unselected case executed")
					}
					continue
				}
				if c.Actual == NotRun {
					t.Fatalf("selected case %s was suppressed", c.ID)
				}
				if c.ID == failID && s.Report.CaseAccepted(c) {
					t.Fatal("failure hidden")
				}
			}
			if s.Report.Accepted() {
				t.Fatal("subset with a failed case accepted")
			}
		})
	}
}

func TestGroupedIncompleteSelectionStopsLaterGroups(t *testing.T) {
	s := completionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.Execute = func(context.Context, string, ...string) error { cancel(); return nil }
	if err := s.Run(ctx); err == nil {
		t.Fatal("interrupted selection reported complete")
	}
	for _, c := range s.Report.Results() {
		if c.ID == "D1-01" && c.Actual != NotRun {
			t.Fatal("DNS group ran after interrupted serial phase")
		}
	}
}

func completionFixture(t *testing.T) *Suite {
	t.Helper()
	dir := t.TempDir()
	features := filepath.Join(dir, "test/e2e/features")
	if err := os.MkdirAll(features, 0700); err != nil {
		t.Fatal(err)
	}
	feature := `Feature: Group completion
  @selected
  Scenario: N1-01 first serial case
    Given native injection validates CNI redirection without istio-init
  @selected
  Scenario: N1-02 second serial case
    Given the shared Istio installation and test workloads are ready
  @selected @dns @dns-lane-records
  Scenario: D1-01 selected DNS group
    Given the shared Istio installation and test workloads are ready
  @excluded @dns @dns-lane-bypass
  Scenario: OTHER unselected group
    Given the shared Istio installation and test workloads are ready
`
	for file, data := range map[string]string{filepath.Join(features, "completion.feature"): feature, filepath.Join(dir, "environment.json"): `{"inputs":"test"}`} {
		if err := os.WriteFile(file, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{Profile: "calico-istio", Mode: "enforce", Dir: dir}
	for _, id := range []string{"N1-01", "N1-02", "D1-01", "OTHER"} {
		r.Cases = append(r.Cases, CaseResult{ID: id, Actual: NotRun})
	}
	return &Suite{Root: dir, State: dir, Artifacts: dir, Report: r, Tags: "@selected", Execute: func(context.Context, string, ...string) error { return nil }}
}
