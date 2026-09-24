package suite

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAcceptanceNeverHidesErrorsOrUnexpectedResults(t *testing.T) {
	for _, mode := range []string{"baseline", "enforce"} {
		for _, actual := range []string{Satisfied, Violated, ExecutionError, Inconclusive, NotRun} {
			r := Report{Mode: mode, Cases: []CaseResult{{ID: "N1-01", Expected: Violated, Actual: actual}}}
			want := mode == "baseline" && actual == Violated || mode == "enforce" && actual == Satisfied
			if got := r.CaseAccepted(r.Cases[0]); got != want {
				t.Fatalf("mode=%s actual=%s accepted=%t want=%t", mode, actual, got, want)
			}
		}
	}
}

func TestInventoryExpandsExamplesAndRejectsDuplicateIDs(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "test/e2e/features")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	feature := "Feature: coverage\n Scenario Outline: <id> probe <port>\n  Then the egress contract \"deny\" is evaluated using complete evidence for this case\n Examples:\n  | id | port |\n  | N1-01 | 443 |\n  | N1-02 | 8443 |\n"
	path := filepath.Join(dir, "test.feature")
	if err := os.WriteFile(path, []byte(feature), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewReport(root, t.TempDir(), "enforce", "abc", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Cases) != 2 || r.Cases[1].ID != "N1-02" || r.Cases[0].Actual != NotRun {
		t.Fatalf("bad inventory: %+v", r.Cases)
	}
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(feature, "N1-02", "N1-01")), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewReport(root, t.TempDir(), "enforce", "abc", false); err == nil {
		t.Fatal("duplicate case accepted")
	}
}

func TestReportKeepsSecurityViolationVisibleAcrossFormats(t *testing.T) {
	dir := t.TempDir()
	r := Report{Mode: "baseline", Profile: "istio-only", Dir: dir, Finished: time.Now(), Cases: []CaseResult{{ID: "N1-01", Name: "direct UDP", Requirement: "deny", Expected: Violated, Actual: Violated, Reason: "receiver got packet", Evidence: "N1-01/"}}}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"not fail-closed", "❌ violated", "✅ PASS", "N1-01"} {
		if !strings.Contains(string(data), fragment) {
			t.Fatalf("missing %q in %s", fragment, data)
		}
	}
	data, _ = os.ReadFile(filepath.Join(dir, "case-results.json"))
	var roundtrip Report
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip.Cases[0].Actual != Violated {
		t.Fatal("lost violation")
	}
	data, _ = os.ReadFile(filepath.Join(dir, "junit.xml"))
	var junit struct {
		Failures int `xml:"failures,attr"`
		Cases    []struct {
			Name string `xml:"name,attr"`
		} `xml:"testcase"`
	}
	if err := xml.Unmarshal(data, &junit); err != nil {
		t.Fatal(err)
	}
	if junit.Failures != 0 || len(junit.Cases) != 1 {
		t.Fatalf("bad baseline JUnit: %s", data)
	}
	r.Mode = "enforce"
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(filepath.Join(dir, "junit.xml"))
	if err := xml.Unmarshal(data, &junit); err != nil {
		t.Fatal(err)
	}
	if junit.Failures != 1 {
		t.Fatalf("enforcement hid violation: %s", data)
	}
}

func TestSetupFailureRetainsUnexecutedCases(t *testing.T) {
	r := Report{Mode: "baseline", Dir: t.TempDir(), Cases: []CaseResult{{ID: "N1-01", Expected: Violated, Actual: NotRun}}}
	r.RunError = "kind creation failed"
	if r.Accepted() {
		t.Fatal("setup failure accepted")
	}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(r.Dir, "summary.md"))
	if !strings.Contains(string(b), "⏸ not_run") || !strings.Contains(string(b), "kind creation failed") {
		t.Fatalf("missing failure: %s", b)
	}
	if err := r.Record("missing", Satisfied, "", "", time.Second); err == nil {
		t.Fatal("unknown case accepted")
	}
	if err := r.Record("N1-01", Satisfied, "", "", time.Second); err != nil {
		t.Fatal(err)
	}
	if r.Cases[0].DurationSeconds != 1 || !strings.Contains(r.Markdown(), "1.000s") || !strings.Contains(string(r.junit()), `time="1"`) {
		t.Fatal("case duration missing from one of the reports")
	}
	if err := r.Record("N1-01", Violated, "", "", time.Second); err == nil {
		t.Fatal("duplicate result accepted")
	}
}

func TestInterruptedAfterLastCaseCannotReportAcceptance(t *testing.T) {
	r := Report{Mode: "enforce", Dir: t.TempDir(), Cases: []CaseResult{{ID: "N1-01", Actual: Satisfied}}}
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	if r.Acceptance != "FAIL" || r.Accepted() {
		t.Fatal("unfinished run accepted")
	}
	r.Finished = time.Now()
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	if !r.Accepted() {
		t.Fatal("completed successful run rejected")
	}
}

func TestBaselineCannotExemptPermittedPaths(t *testing.T) {
	r := Report{Mode: "baseline"}
	for _, c := range []CaseResult{{ID: "N4-01", Requirement: "gateway"}, {ID: "N5-01", Requirement: "allow"}, {ID: "P0-01"}} {
		c.Actual, c.Expected = Violated, Violated
		if r.CaseAccepted(c) {
			t.Fatalf("baseline exempted required working path: %+v", c)
		}
	}
}

func TestPhaseAndSlowestReportsUseWallTimes(t *testing.T) {
	start := time.Now()
	r := Report{Started: start, Finished: start.Add(3 * time.Second), Cases: []CaseResult{
		{ID: "fast", Name: "fast", Actual: Satisfied, DurationSeconds: 1},
		{ID: "slow", Name: "slow", Actual: Satisfied, DurationSeconds: 2, Phases: []PhaseTiming{{Name: "health-before", Seconds: 0.5}}},
	}, Operations: []OperationTiming{{Script: "parallel-a", Seconds: 2}, {Script: "parallel-b", Seconds: 2}}}
	m := r.Markdown()
	if !strings.Contains(m, "Suite wall time: 3.000s") || !strings.Contains(m, "| slow | health-before | 0.500s") {
		t.Fatal(m)
	}
	slow := strings.Index(m, "Slowest executed cases:")
	if strings.Index(m[slow:], "| slow |") > strings.Index(m[slow:], "| fast |") {
		t.Fatal("slowest table not sorted")
	}
	if r.Cases[0].ID != "fast" {
		t.Fatal("rendering reordered inventory")
	}
}
