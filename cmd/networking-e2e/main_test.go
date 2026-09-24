package main

import (
	"encoding/json"
	"github.com/egress-gateway/egress-gateway-networking/test/e2e/suite"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutputDirectoriesStaySeparate(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name      string
		state     string
		artifacts string
		wantError bool
	}{
		{name: "default siblings", state: ".e2e/state", artifacts: ".e2e/artifacts"},
		{name: "shared name prefix", state: ".e2e/state", artifacts: ".e2e/state-reports"},
		{name: "separate nested paths", state: "private/state", artifacts: "reports/networking"},
		{name: "same directory", state: ".e2e/state", artifacts: ".e2e/state", wantError: true},
		{name: "artifacts inside state", state: ".e2e/state", artifacts: ".e2e/state/reports", wantError: true},
		{name: "state inside artifacts", state: ".e2e/artifacts/state", artifacts: ".e2e/artifacts", wantError: true},
		{name: "artifacts at e2e parent", state: ".e2e/state", artifacts: ".e2e", wantError: true},
		{name: "artifacts at repository root", state: ".e2e/state", artifacts: ".", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOutputPaths(filepath.Join(root, tc.state), filepath.Join(root, tc.artifacts))
			if (err != nil) != tc.wantError {
				t.Fatalf("state=%q artifacts=%q: error=%v, wantError=%t", tc.state, tc.artifacts, err, tc.wantError)
			}
		})
	}
}

func TestCIFailureFinalizesCompleteUnexecutedInventory(t *testing.T) {
	parent := t.TempDir()
	r := suite.Report{Dir: filepath.Join(parent, "run-inventory"), Mode: "baseline", Started: time.Now(), Cases: []suite.CaseResult{{ID: "N1-01", Expected: suite.Violated, Actual: suite.NotRun}}}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	if err := printSummary(parent, "tools=failure network=skipped"); err == nil {
		t.Fatal("failed setup summary returned success")
	}
	b, err := os.ReadFile(filepath.Join(r.Dir, "case-results.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got suite.Report
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Finished.IsZero() || !strings.Contains(got.RunError, "tools=failure") || got.Cases[0].Actual != suite.NotRun || got.Acceptance != "FAIL" {
		t.Fatalf("incorrect failure report: %+v", &got)
	}
	for _, name := range []string{"summary.md", "junit.xml"} {
		b, err := os.ReadFile(filepath.Join(r.Dir, name))
		if err != nil || !strings.Contains(string(b), "tools=failure") {
			t.Fatalf("missing phase in %s: %v", name, err)
		}
	}
}
