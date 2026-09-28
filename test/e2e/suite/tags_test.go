package suite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSelectedFailureDoesNotSuppressOtherCases(t *testing.T) {
	s := completionFixture(t)
	calls := 0
	s.Execute = func(context.Context, string, ...string) error {
		calls++
		if calls == 1 {
			return errors.New("fixture failed")
		}
		return nil
	}
	if err := s.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	results := s.Report.Results()
	if results[0].Actual != ExecutionError || results[1].Actual != Satisfied || results[2].Actual != NotRun {
		t.Fatalf("incorrect results: %+v", results)
	}
}
func TestInterruptedSelectionCannotReportComplete(t *testing.T) {
	s := completionFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.Execute = func(context.Context, string, ...string) error { cancel(); return nil }
	if err := s.Run(ctx); err == nil {
		t.Fatal("interrupted selection passed")
	}
	if s.Report.Results()[1].Actual != NotRun {
		t.Fatal("case executed after cancellation")
	}
}
func completionFixture(t *testing.T) *Suite {
	t.Helper()
	dir := t.TempDir()
	features := filepath.Join(dir, "test/e2e/features")
	if err := os.MkdirAll(features, 0700); err != nil {
		t.Fatal(err)
	}
	feature := `Feature: Selection
  @selected
  Scenario: A first case
    Given the independent enrollment bindings are ready
  @selected
  Scenario: B second case
    Given the independent enrollment bindings are ready
  @excluded
  Scenario: OTHER excluded
    Given the independent enrollment bindings are ready
`
	for path, data := range map[string]string{filepath.Join(features, "selection.feature"): feature, filepath.Join(dir, "environment.json"): `{"inputs":"test"}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := &Report{Profile: "calico", Mode: "enforce", Dir: dir}
	for _, id := range []string{"A", "B", "OTHER"} {
		r.Cases = append(r.Cases, CaseResult{ID: id, Actual: NotRun})
	}
	return &Suite{Root: dir, State: dir, Artifacts: dir, Report: r, Tags: "@selected"}
}
