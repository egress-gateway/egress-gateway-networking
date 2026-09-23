package suite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInterruptedOrUnrestoredSuiteLeavesRemainingCasesNotRun(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(map[bool]string{false: "restoration failure", true: "interrupted"}[interrupted], func(t *testing.T) {
			root, state, artifacts := t.TempDir(), t.TempDir(), t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, "test/e2e/features"), 0700); err != nil {
				t.Fatal(err)
			}
			feature := `Feature: failure accounting
  Scenario: N1-01 first probe
    When the "udp" probe targets "external" from "workload" during "gateway-down"
    Then the egress contract "deny" is evaluated
  Scenario: N1-02 later probe
    When the "udp" probe targets "external" from "workload" during "healthy"
    Then the egress contract "deny" is evaluated
`
			if err := os.WriteFile(filepath.Join(root, "test/e2e/features/failure.feature"), []byte(feature), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(state, "environment.json"), []byte(`{"inputs":"test"}`), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := NewReport(root, artifacts, "enforce", "test", false)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			s := Suite{Root: root, State: state, Artifacts: artifacts, Report: report, Execute: func(context.Context, string, ...string) error {
				calls++
				if err := os.WriteFile(filepath.Join(state, "fault-active"), []byte("restore failed"), 0600); err != nil {
					return err
				}
				return errors.New("fixture restoration failed")
			}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if interrupted {
				cancel()
			}
			if err := s.Run(ctx); err == nil {
				t.Fatal("incomplete suite succeeded")
			}
			if interrupted {
				if calls != 0 || report.Cases[0].Actual != NotRun {
					t.Fatal("interrupted suite started a case")
				}
			} else {
				if calls != 1 || report.Cases[0].Actual != ExecutionError {
					t.Fatalf("wrong fault result: calls=%d cases=%+v", calls, report.Cases)
				}
			}
			if report.Cases[1].Actual != NotRun || report.Accepted() {
				t.Fatal("remaining case accepted after interruption/restoration failure")
			}
		})
	}
}
