package environment

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGateReleaseRequiresSameSuccessfulContainer(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"normal", "racing", "exec-error", "wait-error", "replaced-pod", "replaced-container", "restarted", "failed-exit", "oom"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			before := `{"metadata":{"uid":"pod-one"},"status":{"initContainerStatuses":[{"name":"test-gate","containerID":"container-one","restartCount":0,"state":{"running":{}}}]}}`
			after := strings.ReplaceAll(before, `"running":{}`, `"terminated":{"exitCode":0,"reason":"Completed"}`)
			switch name {
			case "replaced-pod":
				after = strings.ReplaceAll(after, "pod-one", "pod-two")
			case "replaced-container":
				after = strings.ReplaceAll(after, "container-one", "container-two")
			case "restarted":
				after = strings.ReplaceAll(after, `"restartCount":0`, `"restartCount":1`)
			case "failed-exit":
				after = strings.ReplaceAll(after, `"exitCode":0`, `"exitCode":1`)
			case "oom":
				after = strings.ReplaceAll(after, "Completed", "OOMKilled")
			}
			for file, body := range map[string]string{"before.json": before, "after.json": after} {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			script := `set -euo pipefail
source "$1"
artifacts=$2
mode=$3
k() {
 case " $* " in
 *" get "*)
   if [[ -e "$artifacts/read-before" ]]; then cat "$artifacts/after.json"
   else touch "$artifacts/read-before"; cat "$artifacts/before.json"; fi;;
 *" exec "*)
   [[ "$mode" != exec-error ]] || return 126
   [[ "$mode" == normal ]] || return 137;;
 *" wait "*) [[ "$mode" != wait-error ]];;
 *) return 127;;
 esac
}
release_gate fixture
`
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "release-test", filepath.Join(root, "test/e2e/scripts/egress-lib.sh"), dir, name)
			out, err := cmd.CombinedOutput()
			want := name == "normal" || name == "racing"
			if (err == nil) != want {
				t.Fatalf("accepted=%t want=%t error=%v output=%s", err == nil, want, err, out)
			}
		})
	}
}
