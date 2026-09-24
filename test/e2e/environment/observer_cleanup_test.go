package environment

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStartupObserverCleanupVisitsEveryJobAfterFailure(t *testing.T) {
	lib, err := filepath.Abs("../scripts/calico-fault-lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "stop-failed", "wait-failed"} {
		t.Run(mode, func(t *testing.T) {
			script := `set -euo pipefail
source "$1"
mode=$2
cluster=owned test_id=case address=192.0.2.1:9001
jobs=(101 102 103) roles=(receiver sender drops)
stops=0 joins=0
docker() { stops=$((stops+1)); [[ "$mode" != stop-failed || "$stops" != 1 ]]; }
kill() { return 1; }
wait() {
 [[ "$stops" == 3 ]] || exit 92
 joins=$((joins+1))
 [[ "$mode" != wait-failed || "$joins" != 1 ]]
}
rc=0
finish_observers || rc=$?
[[ "$stops" == 3 && "$joins" == 3 && ${#jobs[@]} == 0 && ${#roles[@]} == 0 ]]
if [[ "$mode" == success ]]; then [[ "$rc" == 0 ]]; else [[ "$rc" != 0 ]]; fi
finish_observers
[[ "$stops" == 3 && "$joins" == 3 ]]
`
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "observer-test", lib, mode)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
		})
	}
}

func TestStartupTupleUsesFinalProbeSource(t *testing.T) {
	lib, err := filepath.Abs("../scripts/calico-observation-lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := `set -euo pipefail
source "$1"
artifacts=$2
cluster=owned test_id=case address=10.96.0.1:8080 drop_address=10.244.0.5:8080
source_ip=10.244.0.2
docker() { :; }
true & drop_pid=$!
printf '%s\n' '{"event":"netfilter-drop","remote":"10.244.0.3:40000","interface":"cali123"}' > "$artifacts/drops.jsonl"
source_ip=10.244.0.3
calico_observe_finish
jq -e '.source=="10.244.0.3" and .original_destination=="10.96.0.1:8080" and .receiver_endpoint=="10.244.0.5:8080"' "$artifacts/tuple.json"
jq -e '.source_ip=="10.244.0.3" and .interface=="cali123"' "$artifacts/enforcement.json"
`
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "tuple-test", lib, t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}
