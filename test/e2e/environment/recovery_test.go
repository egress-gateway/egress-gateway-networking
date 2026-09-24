package environment

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellRecoveryCommandsKeepFailureStateUntilVerified(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ phase, fail string }{{"repair", "wait"}, {"repair", "exec"}, {"sidecar-stop", "exec"}, {"repair", "none"}, {"sidecar-stop", "none"}, {"gateway-down", "converging"}, {"gateway-down", "proof"}} {
		t.Run(tc.phase+"-"+tc.fail, func(t *testing.T) {
			artifacts := t.TempDir()
			script := `set -euo pipefail
source "$1"
artifacts=$2
phase=$3
failure=$4
fault_pod=fixture
test_id=case
origin=192.0.2.1
recovery_failed=false
trap 'printf "%s" "$recovery_failed" > "$artifacts/recovery-state"' EXIT
k() {
 case " $* " in
  *" wait "*) [[ "$failure" != wait ]];;
  *" exec "*) [[ "$failure" != exec ]] || return 1
    id='' count=1
    while (($#)); do
      case "$1" in --id) id=$2; shift;; --successes) count=$2; shift;; esac
      shift
    done
    printf '%s\n' "$id" >> "$artifacts/request-ids"
    if [[ "$failure" == converging && "$id" == case-recovery-ready || "$failure" == proof && "$id" == case-recovery ]]; then
      printf '{"id":"%s","success":false}\n' "$id"
    fi
    for ((i=0;i<count;i++)); do printf '{"id":"%s","success":true}\n' "$id"; done;;
 esac
}
epod() { printf '%s\n' fixture; }
verify_recovery
`
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "recovery-test", filepath.Join(root, "test/e2e/scripts/egress-lib.sh"), artifacts, tc.phase, tc.fail)
			output, runErr := cmd.CombinedOutput()
			data, err := os.ReadFile(filepath.Join(artifacts, "recovery-state"))
			if err != nil {
				t.Fatalf("state missing: %v %s", err, output)
			}
			if tc.fail == "none" || tc.fail == "converging" {
				if runErr != nil || string(data) != "false" {
					t.Fatalf("successful recovery stayed blocked: %v %s %s", runErr, data, output)
				}
				ids, err := os.ReadFile(filepath.Join(artifacts, "request-ids"))
				if err != nil || !strings.HasPrefix(string(ids), "case-recovery-ready\n") || strings.Count(string(ids), "\n") != 2 {
					t.Fatalf("readiness and proof were not separated: %s %v", ids, err)
				}
			} else if runErr == nil || strings.TrimSpace(string(data)) != "true" {
				t.Fatalf("failed recovery released guard: %v %s %s", runErr, data, output)
			}
		})
	}
}
