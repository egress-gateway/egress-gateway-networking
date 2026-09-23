package environment

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func testEnvironment(t *testing.T) (*Environment, *[]string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "install"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "install", "versions.env"), []byte("version=test"), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls []string
	e := &Environment{Root: root, State: filepath.Join(root, "state"), Artifacts: filepath.Join(root, "artifacts")}
	e.Execute = func(_ context.Context, script string, _ ...string) error { calls = append(calls, script); return nil }
	e.Test = func(context.Context) error { calls = append(calls, "suite"); return nil }
	return e, &calls
}

func TestSetupFailureDiagnosesBeforeCleanup(t *testing.T) {
	e, calls := testEnvironment(t)
	execute := e.Execute
	e.Execute = func(ctx context.Context, script string, args ...string) error {
		_ = execute(ctx, script, args...)
		if script == "install/scripts/install.sh" {
			return errors.New("install failed")
		}
		return nil
	}
	if err := e.Run(t.Context(), "e2e"); err == nil {
		t.Fatal("expected failure")
	}
	diag := slices.Index(*calls, "environments/kind/diagnostics.sh")
	down := slices.Index(*calls, "environments/kind/down.sh")
	if diag < 0 || down <= diag || slices.Contains(*calls, "suite") {
		t.Fatalf("unsafe order: %v", *calls)
	}
}

func TestExistingStateNeverAcquiresOwnership(t *testing.T) {
	e, calls := testEnvironment(t)
	if err := os.Mkdir(e.State, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(t.Context(), "e2e"); err == nil {
		t.Fatal("expected refusal")
	}
	if len(*calls) != 0 {
		t.Fatalf("touched existing state: %v", *calls)
	}
}

func TestRetainedFailureDoesNotDeleteEnvironment(t *testing.T) {
	e, calls := testEnvironment(t)
	if err := e.Run(t.Context(), "up"); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	e.Test = func(context.Context) error { return errors.New("assertion failed") }
	if err := e.Run(t.Context(), "test"); err == nil {
		t.Fatal("expected failure")
	}
	if slices.Contains(*calls, "environments/kind/down.sh") || slices.Contains(*calls, "environments/kind/up.sh") {
		t.Fatalf("retained mode changed lifecycle: %v", *calls)
	}
	if _, err := os.Stat(e.State); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityFailurePreventsFixtureMutationAndCleanup(t *testing.T) {
	e, calls := testEnvironment(t)
	if err := e.Run(t.Context(), "up"); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	e.Execute = func(_ context.Context, script string, _ ...string) error {
		*calls = append(*calls, script)
		if strings.HasSuffix(script, "verify.sh") || strings.HasSuffix(script, "down.sh") {
			return errors.New("identity mismatch")
		}
		return nil
	}
	if err := e.Run(t.Context(), "test"); err == nil {
		t.Fatal("expected identity refusal")
	}
	if slices.Contains(*calls, "suite") {
		t.Fatalf("ran suite: %v", *calls)
	}
	if err := e.Run(t.Context(), "down"); err == nil {
		t.Fatal("expected cleanup refusal")
	}
	if _, err := os.Stat(e.State); err != nil {
		t.Fatal("lost ownership evidence", err)
	}
}

func TestChangedInstallInputsRefuseReuseButAllowCleanup(t *testing.T) {
	e, _ := testEnvironment(t)
	if err := e.Run(t.Context(), "up"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.Root, "install", "versions.env"), []byte("version=changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Run(t.Context(), "test"); err == nil {
		t.Fatal("accepted stale environment")
	}
	if err := e.Run(t.Context(), "down"); err != nil {
		t.Fatal(err)
	}
}

func TestKeepPreservesFailedSetup(t *testing.T) {
	e, calls := testEnvironment(t)
	e.Keep = true
	e.Test = func(context.Context) error { return errors.New("failed") }
	if err := e.Run(t.Context(), "e2e"); err == nil {
		t.Fatal("expected failure")
	}
	if slices.Contains(*calls, "environments/kind/down.sh") {
		t.Fatalf("deleted retained environment: %v", *calls)
	}
}

func TestShellCleanupRefusesNodeIdentityMismatch(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, mismatch := range []string{"node ID", "owner mount"} {
		t.Run(mismatch, func(t *testing.T) {
			state := t.TempDir()
			bin := t.TempDir()
			write := func(path, contents string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(contents), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(state, "environment.json"), `{"cluster":"networking-e2e-unit"}`, 0o600)
			write(filepath.Join(state, "node-id"), "original\n", 0o600)
			id, owner := "original", filepath.Join(state, "owner")
			if mismatch == "node ID" {
				id = "replacement"
			} else {
				owner = "/unrelated/owner"
			}
			info := []any{map[string]any{"Id": id, "Config": map[string]any{"Labels": map[string]string{"io.x-k8s.kind.cluster": "networking-e2e-unit"}}, "Mounts": []any{map[string]any{"Source": owner, "Destination": "/etc/networking-e2e-owner", "RW": false}}}}
			data, err := json.Marshal(info)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(bin, "inspect.json"), string(data), 0o600)
			write(filepath.Join(bin, "docker"), "#!/bin/sh\ncase \"$1\" in info) exit 0;; inspect) cat \"$(dirname \"$0\")/inspect.json\";; *) exit 2;; esac\n", 0o700)
			write(filepath.Join(bin, "kind"), "#!/bin/sh\ntouch \"$(dirname \"$0\")/deleted\"\n", 0o700)
			cmd := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "environments/kind/down.sh"), "--state-dir", state)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("unsafe cleanup succeeded: %s", output)
			}
			if _, err := os.Stat(filepath.Join(bin, "deleted")); !os.IsNotExist(err) {
				t.Fatal("invoked kind delete on an unrelated node")
			}
		})
	}
}

func TestReceiverCleanupValidatesAllIdentitiesBeforeDeletion(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, mismatch := range []string{"id", "mount", "label", "none"} {
		t.Run(mismatch, func(t *testing.T) {
			state, bin := t.TempDir(), t.TempDir()
			write := func(path, body string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(state, "environment.json"), `{"cluster":"networking-e2e-unit"}`, 0600)
			for _, role := range []string{"origin", "quic"} {
				id, owner, label := role, filepath.Join(state, "owner"), "networking-e2e-unit"
				if role == "quic" {
					switch mismatch {
					case "id":
						id = "replacement"
					case "mount":
						owner = "/unrelated/owner"
					case "label":
						label = "unrelated"
					}
				}
				write(filepath.Join(state, role+"-id"), role, 0600)
				info := []any{map[string]any{"Id": id, "Config": map[string]any{"Labels": map[string]string{"networking.e2e.cluster": label}}, "Mounts": []any{map[string]any{"Source": owner, "Destination": "/owner", "RW": false}}}}
				data, err := json.Marshal(info)
				if err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(bin, "networking-e2e-unit-"+role+".json"), string(data), 0600)
			}
			write(filepath.Join(bin, "docker"), "#!/bin/sh\ncase \"$1\" in inspect) cat \"$(dirname \"$0\")/$2.json\";; rm) printf '%s\\n' \"$3\" >> \"$(dirname \"$0\")/deleted\";; *) exit 2;; esac\n", 0700)
			cmd := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "test/e2e/scripts/egress-down.sh"), "--state-dir", state)
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if mismatch == "none" {
				if err != nil {
					t.Fatalf("owned cleanup failed: %s %v", out, err)
				}
				data, err := os.ReadFile(filepath.Join(bin, "deleted"))
				if err != nil || len(strings.Fields(string(data))) != 2 {
					t.Fatalf("missing owned cleanup: %s %v", data, err)
				}
			} else {
				if err == nil {
					t.Fatalf("mismatch accepted: %s", out)
				}
				if _, err := os.Stat(filepath.Join(bin, "deleted")); !os.IsNotExist(err) {
					t.Fatal("deleted a receiver before validating all identities")
				}
			}
		})
	}
}
