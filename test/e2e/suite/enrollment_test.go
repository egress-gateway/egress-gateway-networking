package suite

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBrokenDNSVerdictsPreserveViolationsAndErrors(t *testing.T) {
	cleanup := errors.New("recovery failed")
	for _, tc := range []struct {
		actual, functionality string
		err                   error
		wantError             bool
	}{
		{Violated, "not_evaluated", nil, false},
		{Satisfied, "not_satisfied", nil, false},
		{Satisfied, "satisfied", nil, true},
		{Inconclusive, "not_evaluated", nil, true},
		{ExecutionError, "not_evaluated", cleanup, true},
		{Violated, "not_evaluated", cleanup, true},
	} {
		t.Run(tc.actual+tc.functionality, func(t *testing.T) {
			actual, reason, err := brokenDNSVerdict(tc.actual, tc.functionality, "delivery proved", tc.err)
			if actual != tc.actual || (err != nil) != tc.wantError {
				t.Fatalf("%s %s %v", actual, reason, err)
			}
			if tc.actual == Violated && reason != "delivery proved" {
				t.Fatal("violation evidence lost")
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatal("cleanup failure lost")
			}
		})
	}
}

func TestStartupContractRequiresExercisedFailureAndUnstartedBusiness(t *testing.T) {
	base := `{"uid":"pod-id","init":[{"name":"istio-proxy","restartCount":1},{"name":"business-marker","state":{"waiting":{}}}],"app":[{"name":"probe","state":{"waiting":{}}}]}`
	for name, body := range map[string]string{"blocked": base, "not-exercised": strings.Replace(base, `"restartCount":1`, `"restartCount":0`, 1), "business-ran": strings.Replace(base, `"name":"business-marker","state":{"waiting":{}}`, `"name":"business-marker","state":{"terminated":{"exitCode":0}}`, 1), "app-ran": strings.Replace(base, `"name":"probe","state":{"waiting":{}}`, `"name":"probe","state":{"running":{}}`, 1), "no-identity": strings.Replace(base, `"uid":"pod-id"`, `"uid":""`, 1)} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "startup.json"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			state, reason, err := evaluateEnrollment(dir, "case", "startup")
			if name == "blocked" {
				if err != nil || state != Satisfied {
					t.Fatalf("%s %s %v", state, reason, err)
				}
			} else if err == nil && state == Satisfied {
				t.Fatal("invalid startup evidence accepted")
			}
		})
	}
}
