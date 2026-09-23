package suite

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrNegativeDetected = errors.New("negative control correctly detected the deliberate security violation; isolation restored")

func NewNegativeReport(root, dir, profile, mode, sha string, dirty bool) (*Report, error) {
	if profile != "calico-istio" || mode != "enforce" {
		return nil, errors.New("negative control requires calico-istio + enforce")
	}
	r, err := NewProfileReport(root, dir, profile, mode, sha, dirty)
	if err != nil {
		return nil, err
	}
	r.Configuration["purpose"] = "detector negative control; excluded from security acceptance counts"
	r.Cases = []CaseResult{{ID: "X-ALLOW", Name: "X-ALLOW Additive allow must be reported as a security violation", Requirement: "Deny the forbidden TCP tuple", Actual: NotRun}}
	return r, nil
}

// RunNegative deliberately uses the same deny evaluator and a separate report.
// Its exit is nonzero even when the detector control is correctly identified.
func (s *Suite) RunNegative(ctx context.Context) error {
	id := strings.ToLower(rand.Text()[:20])
	dir := filepath.Join(s.Artifacts, "X-ALLOW")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	started := time.Now()
	err := s.Execute(ctx, "test/e2e/scripts/network-negative.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id)
	actual, reason := ExecutionError, "negative operation did not complete"
	restored, restoreReason := "", ""
	if err == nil {
		actual, reason, err = evaluateNetwork(dir, id, "deny", egressInputs{Protocol: "tcp", Target: "np-wrong", Phase: "healthy"})
		var restoreErr error
		restored, restoreReason, restoreErr = evaluateNetwork(filepath.Join(dir, "restored"), id+"-restored", "deny", egressInputs{Protocol: "tcp", Target: "np-wrong", Phase: "healthy"})
		err = errors.Join(err, restoreErr)
	}
	verified := err == nil && actual == Violated && restored == Satisfied
	if restored == Satisfied {
		marker := filepath.Join(s.State, "fault-active")
		data, readErr := os.ReadFile(marker)
		if readErr == nil && strings.TrimSpace(string(data)) == "negative-"+id {
			err = errors.Join(err, os.Remove(marker))
		} else {
			err = errors.Join(err, errors.New("negative recovery marker identity mismatch"))
		}
	}
	if err != nil {
		actual, reason = ExecutionError, err.Error()
		verified = false
	}
	if e := s.Report.Record("X-ALLOW", actual, reason, "X-ALLOW/", time.Since(started)); e != nil {
		return errors.Join(err, e)
	}
	data, _ := json.MarshalIndent(map[string]any{"verified": verified, "observed": actual, "restored": restored, "recovery_reason": restoreReason}, "", "  ")
	if e := os.WriteFile(filepath.Join(s.Artifacts, "negative-control.json"), data, 0600); e != nil {
		return errors.Join(err, e)
	}
	if !verified {
		return errors.Join(err, fmt.Errorf("negative control failed: observation=%s recovery=%s", actual, restored))
	}
	return ErrNegativeDetected
}

func (r *Report) NegativeControlConfirmed() bool {
	if r.Configuration["purpose"] == "" || r.Profile != "calico-istio" || r.Mode != "enforce" || r.Finished.IsZero() || r.RunError != ErrNegativeDetected.Error() || len(r.Cases) != 1 || r.Cases[0].ID != "X-ALLOW" || r.Cases[0].Actual != Violated {
		return false
	}
	var control struct {
		Verified bool   `json:"verified"`
		Observed string `json:"observed"`
		Restored string `json:"restored"`
	}
	data, err := os.ReadFile(filepath.Join(r.Dir, "negative-control.json"))
	if err != nil || json.Unmarshal(data, &control) != nil || !control.Verified || control.Observed != Violated || control.Restored != Satisfied {
		return false
	}
	var terminal struct {
		Expected bool `json:"expected_negative"`
	}
	data, err = os.ReadFile(filepath.Join(r.Dir, "run.json"))
	return err == nil && json.Unmarshal(data, &terminal) == nil && terminal.Expected
}
