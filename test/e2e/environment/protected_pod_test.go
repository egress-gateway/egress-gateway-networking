package environment

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedPodRenderingKeepsConfigurationLocal(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"kubectl": "#!/bin/sh\nprintf 10.96.0.12\n", "kubeconfig": "fixture"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Pod", "Deployment"} {
		t.Run(kind, func(t *testing.T) {
			pod := map[string]any{"metadata": map[string]any{"labels": map[string]string{"networking.egress/protected": "true"}, "annotations": map[string]string{"proxy.istio.io/config": `{"holdApplicationUntilProxyStarts":true,"proxyMetadata":{"OTHER":"kept"}}`}}, "spec": map[string]any{"hostAliases": []any{map[string]any{"ip": "10.0.0.1", "hostnames": []string{"kept.test", "istiod.istio-system.svc"}}}}}
			input := pod
			if kind == "Deployment" {
				input = map[string]any{"spec": map[string]any{"template": pod}}
			}
			input["kind"] = kind
			data, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "install/scripts/protected-pod.sh"), "--kubeconfig", filepath.Join(dir, "kubeconfig"), "--context", "owned")
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
			cmd.Stdin = strings.NewReader(string(data))
			out, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			var rendered map[string]any
			if err = json.Unmarshal(out, &rendered); err != nil {
				t.Fatal(err)
			}
			if kind == "Deployment" {
				rendered = rendered["spec"].(map[string]any)["template"].(map[string]any)
			}
			annotation := rendered["metadata"].(map[string]any)["annotations"].(map[string]any)["proxy.istio.io/config"].(string)
			var config struct {
				Hold     bool              `json:"holdApplicationUntilProxyStarts"`
				Metadata map[string]string `json:"proxyMetadata"`
			}
			if err = json.Unmarshal([]byte(annotation), &config); err != nil {
				t.Fatal(err)
			}
			if !config.Hold || config.Metadata["OTHER"] != "kept" || config.Metadata["ISTIO_META_DNS_CAPTURE"] != "true" {
				t.Fatalf("lost configuration: %s", annotation)
			}
			aliases, _ := json.Marshal(rendered["spec"].(map[string]any)["hostAliases"])
			if !strings.Contains(string(aliases), "kept.test") || !strings.Contains(string(aliases), "10.96.0.12") || strings.Count(string(aliases), `"istiod.istio-system.svc"`) != 1 {
				t.Fatalf("incorrect aliases: %s", aliases)
			}
		})
	}
}
