package suite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
