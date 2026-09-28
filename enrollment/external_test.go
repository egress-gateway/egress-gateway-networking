package enrollment_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// This consumer has its own module and runs outside the checkout. The replace
// selects the candidate source at build time, not a runtime asset directory.
func TestIndependentModuleCanGenerateOffline(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.test/consumer\n\ngo 1.26.0\n\nrequire github.com/egress-gateway/egress-gateway-networking v0.0.0\n\nreplace github.com/egress-gateway/egress-gateway-networking => " + root + "\n",
	}
	source, err := os.ReadFile(filepath.Join(root, "examples/static/main.go"))
	if err != nil {
		t.Fatal(err)
	}
	files["main.go"] = string(source)

	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "go.sum"), sum, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "go", "build", "-mod=mod", "-o", filepath.Join(dir, "consumer"), ".")
	cmd.Dir = dir
	// Build-time dependency resolution is allowed; only generation is offline.
	// GOPROXY=off here would depend on unrelated modules already being cached.
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("external build: %v\n%s", err, out)
	}
	empty := t.TempDir()
	cmd = exec.CommandContext(t.Context(), filepath.Join(dir, "consumer"))
	cmd.Dir = empty
	cmd.Env = []string{"HOME=" + empty, "KUBECONFIG=" + filepath.Join(empty, "missing")}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline generation: %v\n%s", err, out)
	}
}
