// Package environment coordinates the suite's explicitly owned kind environment.
package environment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Executor func(context.Context, string, ...string) error

type Environment struct {
	Root, State, Artifacts, Cluster string
	Profile                         string
	ProxySpec                       string
	PolicyTest                      func(context.Context) error
	Keep                            bool
	Execute                         Executor
	Test                            func(context.Context) error
}

type receipt struct {
	Cluster string `json:"cluster"`
	Profile string `json:"profile,omitempty"`
	Inputs  string `json:"inputs"`
	Ready   bool   `json:"ready"`
}

// Run uses one environment per suite. Retained test failures never trigger down.
func (e *Environment) Run(ctx context.Context, mode string) (result error) {
	if mode != "e2e" && mode != "up" && mode != "test" && mode != "down" && mode != "negative" {
		return fmt.Errorf("unknown mode %q", mode)
	}
	if e.Profile == "" {
		e.Profile = "istio-only"
	}
	if e.Profile != "istio-only" && e.Profile != "calico-istio" {
		return fmt.Errorf("unknown profile %q", e.Profile)
	}
	create := mode == "e2e" || mode == "up"
	if create {
		if e.Cluster == "" {
			e.Cluster = "networking-e2e-" + rand.Text()[:10]
		}
		// rand.Text is uppercase base32; cluster names use lowercase DNS labels.
		e.Cluster = strings.ToLower(e.Cluster)
		if !regexp.MustCompile(`^networking-e2e-[a-z0-9-]+$`).MatchString(e.Cluster) {
			return errors.New("cluster name must start with networking-e2e- and use DNS label characters")
		}
		if err := os.MkdirAll(filepath.Dir(e.State), 0o700); err != nil {
			return err
		}
		if err := os.Mkdir(e.State, 0o700); err != nil {
			return fmt.Errorf("refusing existing or inaccessible state %s: %w", e.State, err)
		}
	} else if _, err := os.Stat(e.State); err != nil {
		return fmt.Errorf("retained environment required: %w", err)
	}
	lock := filepath.Join(e.State, "busy")
	if err := os.Mkdir(lock, 0o700); err != nil {
		return fmt.Errorf("environment in use (inspect %s before removing a stale lock): %w", lock, err)
	}
	defer os.Remove(lock)
	if create {
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
			defer cancel()
			e.diagnose(cleanupCtx)
			if mode == "e2e" && !e.Keep {
				result = errors.Join(result, e.down(cleanupCtx))
			}
		}()
		if err := e.setup(ctx, mode == "e2e"); err != nil {
			return err
		}
	} else {
		data, err := os.ReadFile(filepath.Join(e.State, "environment.json"))
		if err != nil {
			return err
		}
		var r receipt
		if err = json.Unmarshal(data, &r); err != nil {
			return err
		}
		e.Cluster = r.Cluster
		if mode == "down" {
			return e.down(ctx)
		}
		inputs, err := e.fingerprint()
		if err != nil {
			return err
		}
		if r.Profile == "" {
			r.Profile = "istio-only"
		}
		if !r.Ready || inputs != r.Inputs || r.Profile != e.Profile {
			return errors.New("environment is incomplete or install inputs changed; run down then up")
		}
		if err = e.phase(ctx, "environments/kind/verify.sh"); err != nil {
			return err
		}
		defer func() {
			diagCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
			defer cancel()
			e.diagnose(diagCtx)
		}()
	}
	if mode == "up" {
		return nil
	}
	if err := e.phase(ctx, "test/e2e/scripts/verify.sh"); err != nil {
		return err
	}
	return e.Test(ctx)
}

func (e *Environment) setup(ctx context.Context, runPolicy bool) error {
	inputs, err := e.fingerprint()
	if err != nil {
		return err
	}
	r := receipt{Cluster: e.Cluster, Profile: e.Profile, Inputs: inputs}
	if err = e.writeReceipt(r); err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(e.State, "owner"), []byte(rand.Text()+"\n"), 0o600); err != nil {
		return err
	}
	if err = e.phase(ctx, "environments/kind/up.sh"); err != nil {
		return err
	}
	if err = e.phase(ctx, "environments/kind/verify.sh"); err != nil {
		return err
	}
	if e.Profile == "calico-istio" {
		if err = e.Execute(ctx, "install/scripts/calico-install.sh", "--kubeconfig", filepath.Join(e.State, "kubeconfig"), "--context", "kind-"+e.Cluster, "--artifacts", e.Artifacts); err != nil {
			return err
		}
		if err = e.phase(ctx, "test/e2e/scripts/np-up.sh"); err != nil {
			return err
		}
		if runPolicy {
			if e.PolicyTest == nil {
				return errors.New("Calico setup requires NP acceptance before Istio")
			}
			if err = e.PolicyTest(ctx); err != nil {
				return err
			}
		}
	}
	installArgs := []string{}
	if e.Profile == "calico-istio" {
		installArgs = append(installArgs, "--enrollment-label", "networking.egress/enabled")
	}
	installArgs = append(installArgs,
		"--kubeconfig", filepath.Join(e.State, "kubeconfig"), "--context", "kind-"+e.Cluster,
		"--cache-dir", filepath.Join(e.Root, ".cache"), "--istiod-values", filepath.Join(e.Root, "test/e2e/config/istiod-values.yaml"))
	if err = e.Execute(ctx, "install/scripts/install.sh", installArgs...); err != nil {
		return err
	}
	if err = e.phase(ctx, "test/e2e/scripts/deploy.sh"); err != nil {
		return err
	}
	if err = e.phase(ctx, "test/e2e/scripts/verify.sh"); err != nil {
		return err
	}
	r.Ready = true
	return e.writeReceipt(r)
}

func (e *Environment) writeReceipt(r receipt) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(e.State, "environment.json"), data, 0o600)
}

func (e *Environment) phase(ctx context.Context, script string) error {
	return e.Execute(ctx, script, "--state-dir", e.State, "--artifacts", e.Artifacts)
}

func (e *Environment) diagnose(ctx context.Context) {
	// Diagnostics are best effort and never replace the original failure.
	_ = e.phase(ctx, "environments/kind/diagnostics.sh")
	_ = e.phase(ctx, "test/e2e/scripts/diagnostics.sh")
}

func (e *Environment) down(ctx context.Context) error {
	if err := e.phase(ctx, "environments/kind/down.sh"); err != nil {
		return err
	}
	return os.RemoveAll(e.State)
}

func (e *Environment) fingerprint() (string, error) {
	h := sha256.New()
	if e.Profile == "calico-istio" {
		fmt.Fprintln(h, e.Profile)
	}
	for _, dir := range []string{"install", "environments/kind", "test/e2e/config", "test/e2e/probe", "go.mod", "go.sum", "baseline", "enrollment", "test/e2e/consumer"} {
		err := filepath.WalkDir(filepath.Join(e.Root, dir), func(path string, d fs.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(e.Root, path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%s\x00%s\x00", rel, data)
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	if e.ProxySpec != "" {
		data, err := os.ReadFile(e.ProxySpec)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "proxy-spec\x00%s", data)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
