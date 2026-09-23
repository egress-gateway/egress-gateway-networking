package suite

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNegativeControlCannotHideReportOrRecoveryFailures(t *testing.T) {
	for _, fault := range []string{"none", "unfinalized", "save-error", "missing-terminal", "unexpected-exit", "restoration", "not-violated"} {
		t.Run(fault, func(t *testing.T) {
			root, err := filepath.Abs("../../..")
			if err != nil {
				t.Fatal(err)
			}
			r, err := NewNegativeReport(root, t.TempDir(), "calico-istio", "enforce", "test", true)
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Cases) != 1 {
				t.Fatal("negative control mixed with safety inventory")
			}
			r.Finished = time.Now()
			r.RunError = ErrNegativeDetected.Error()
			r.Cases[0].Actual = Violated
			terminal := `{"expected_negative":true}`
			control := `{"verified":true,"observed":"violated","restored":"satisfied"}`
			switch fault {
			case "unfinalized":
				r.Finished = time.Time{}
			case "save-error":
				r.RunError += "; report save failed"
			case "unexpected-exit":
				terminal = `{"expected_negative":false}`
			case "restoration":
				control = `{"verified":false,"observed":"violated","restored":"execution_error"}`
			case "not-violated":
				r.Cases[0].Actual = Satisfied
			}
			if err := os.WriteFile(filepath.Join(r.Dir, "negative-control.json"), []byte(control), 0600); err != nil {
				t.Fatal(err)
			}
			if fault != "missing-terminal" {
				if err := os.WriteFile(filepath.Join(r.Dir, "run.json"), []byte(terminal), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := r.NegativeControlConfirmed(); got != (fault == "none") {
				t.Fatalf("confirmation=%t for %s", got, fault)
			}
			if r.Accepted() {
				t.Fatal("detector experiment counted as security acceptance")
			}
		})
	}
}
