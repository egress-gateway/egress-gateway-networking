package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/egress-gateway/egress-gateway-networking/test/e2e/consumer"
	"github.com/egress-gateway/egress-gateway-networking/test/e2e/environment"
	"github.com/egress-gateway/egress-gateway-networking/test/e2e/suite"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (result error) {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: networking-e2e e2e|up|test|down|inventory|summary [flags]")
	}
	if os.Args[1] == "render-enrollment" {
		f := flag.NewFlagSet("render-enrollment", flag.ContinueOnError)
		image := f.String("image", "", "local probe image")
		if err := f.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *image == "" {
			return fmt.Errorf("probe image required")
		}
		return consumer.RenderAcceptance(os.Stdout, *image)
	}
	// Private fixture operation used by Shell; public consumers import enrollment.
	if os.Args[1] == "render-fixture" {
		f := flag.NewFlagSet("render-fixture", flag.ContinueOnError)
		ns := f.String("namespace", "", "policy namespace")
		ip := f.String("istiod-ip", "", "caller-resolved control address")
		resolver := f.String("resolver", "", "private controlled resolver fixture")
		policy := f.Bool("policy", false, "render policy before workload creation")
		only := f.Bool("policy-only", false, "unmeshed isolation fixture")
		if err := f.Parse(os.Args[2:]); err != nil {
			return err
		}
		if *policy {
			if *resolver != "" {
				return consumer.RenderResolverPolicy(os.Stdout, *ns, *ip, *resolver)
			}
			return consumer.RenderPolicy(os.Stdout, *ns, *ip)
		}
		return consumer.RenderPod(os.Stdin, os.Stdout, *ip, os.Getenv("NETWORKING_PROXY_SPEC"), *only)
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	state := flags.String("state-dir", ".e2e/state", "private retained state")
	artifacts := flags.String("artifacts", ".e2e/artifacts", "safe diagnostic output parent")
	cluster := flags.String("cluster", "", "new cluster name (networking-e2e- prefix)")
	keep := flags.Bool("keep", false, "retain the environment after e2e, including failures")
	ciOutcomes := flags.String("ci-outcomes", "", "CI setup and network step outcomes for report finalization")
	profile := flags.String("profile", "istio-only", "istio-only or calico-istio")
	tags := flags.String("tags", "", "development Godog tag subset; unexecuted cases keep full acceptance red")
	acceptance := flags.String("acceptance", "baseline", "baseline or enforce acceptance")
	proxySpec := flags.String("proxy-spec", "", "caller native-sidecar JSON fragment for Calico enrollment acceptance")
	expectedRevision := flags.String("expected-revision", "", "consumer networking commit; must equal installation checkout HEAD")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	var err error
	*root, err = filepath.Abs(*root)
	if err != nil {
		return err
	}
	for _, path := range []*string{state, artifacts} {
		if !filepath.IsAbs(*path) {
			*path = filepath.Join(*root, *path)
		}
	}
	if err := checkOutputPaths(*state, *artifacts); err != nil {
		return err
	}
	if _, err = os.Stat(filepath.Join(*root, "install/versions.env")); err != nil {
		return fmt.Errorf("invalid repository root: %w", err)
	}
	if os.Args[1] == "summary" {
		return printSummary(*artifacts, *ciOutcomes)
	}
	if *acceptance != "baseline" && *acceptance != "enforce" {
		return fmt.Errorf("unknown acceptance mode %q", *acceptance)
	}
	runDir, err := os.MkdirTemp(*artifacts, "run-")
	if os.IsNotExist(err) {
		if err = os.MkdirAll(*artifacts, 0o700); err != nil {
			return err
		}
		runDir, err = os.MkdirTemp(*artifacts, "run-")
	}
	if err != nil {
		return err
	}
	fmt.Printf("Evidence: %s\n", runDir)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()
	bash, err := exec.LookPath("bash")
	if err != nil {
		return err
	}
	if runtime.GOOS == "darwin" {
		if _, err = os.Stat("/opt/homebrew/bin/bash"); err == nil {
			bash = "/opt/homebrew/bin/bash"
		}
	}
	started := time.Now().UTC()
	git := func(args ...string) string {
		c := exec.Command("git", args...)
		c.Dir = *root
		b, _ := c.Output()
		return strings.TrimSpace(string(b))
	}
	sha, dirty := git("rev-parse", "HEAD"), git("status", "--porcelain", "--untracked-files=normal")
	if *expectedRevision != "" && *expectedRevision != sha {
		return fmt.Errorf("networking asset revision mismatch: expected %s, checkout %s", *expectedRevision, sha)
	}
	if *proxySpec != "" {
		if *profile != "calico-istio" {
			return errors.New("proxy-spec requires calico-istio")
		}
		*proxySpec, err = filepath.Abs(*proxySpec)
		if err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	defer func() {
		status := "passed"
		if result != nil {
			status = "failed"
		}
		data, _ := json.MarshalIndent(map[string]any{"command": os.Args[1], "sha": sha, "dirty": dirty != "", "go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "started": started, "finished": time.Now().UTC(), "result": status, "expected_negative": result == suite.ErrNegativeDetected}, "", "  ")
		if err := os.WriteFile(filepath.Join(runDir, "run.json"), data, 0o600); err != nil {
			result = errors.Join(result, err)
		}
	}()
	var report *suite.Report
	if os.Args[1] == "e2e" || os.Args[1] == "test" || os.Args[1] == "inventory" || os.Args[1] == "negative" || os.Args[1] == "inventory-negative" {
		if os.Args[1] == "negative" || os.Args[1] == "inventory-negative" {
			report, err = suite.NewNegativeReport(*root, runDir, *profile, *acceptance, sha, dirty != "")
		} else {
			report, err = suite.NewProfileReport(*root, runDir, *profile, *acceptance, sha, dirty != "")
		}
		if err != nil {
			return err
		}
		if err = report.Save(); err != nil {
			return err
		}
		if os.Args[1] == "inventory" || os.Args[1] == "inventory-negative" {
			return nil
		}
		defer func() {
			report.Finished = time.Now().UTC()
			if data, err := os.ReadFile(filepath.Join(runDir, "kernel.json")); err == nil {
				var nodes []struct {
					Kernel       string `json:"kernel"`
					Architecture string `json:"architecture"`
				}
				if json.Unmarshal(data, &nodes) == nil && len(nodes) == 1 {
					report.Configuration["kernel"] = nodes[0].Kernel + " / " + nodes[0].Architecture
				}
			}
			if result != nil {
				report.RunError = result.Error()
			}
			if err := report.Save(); err != nil {
				result = errors.Join(result, err)
			}
			if !report.Accepted() && result != suite.ErrNegativeDetected {
				result = errors.Join(result, errors.New("network acceptance failed; see summary.md"))
			}
		}()
	}
	execute := func(ctx context.Context, script string, args ...string) (result error) {
		start := time.Now().UTC()
		defer func() {
			if report != nil {
				op := suite.OperationTiming{Script: script, Started: start, Seconds: time.Since(start).Seconds()}
				if result != nil {
					op.Error = result.Error()
				}
				report.AddOperation(op)
			}
		}()
		fmt.Printf("\n> %s\n", script)
		log, err := os.OpenFile(filepath.Join(runDir, strings.ReplaceAll(script, "/", "_")+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer log.Close()
		cmd := exec.CommandContext(ctx, bash, append([]string{filepath.Join(*root, script)}, args...)...)
		cmd.Dir = *root
		cmd.Env = append(os.Environ(), "NETWORKING_E2E_BIN="+self, "NETWORKING_PROXY_SPEC="+*proxySpec)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
		cmd.WaitDelay = 5 * time.Second
		cmd.Stdout = io.MultiWriter(os.Stdout, log)
		cmd.Stderr = io.MultiWriter(os.Stderr, log)
		if err = cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", script, err)
		}
		return nil
	}
	s := suite.Suite{Root: *root, State: *state, Artifacts: runDir, Execute: execute, Report: report, Tags: *tags}
	e := environment.Environment{Root: *root, State: *state, Artifacts: runDir, Cluster: *cluster, Keep: *keep, Profile: *profile, ProxySpec: *proxySpec, Execute: execute, Test: s.Run, PolicyTest: s.RunPolicy}
	if os.Args[1] == "negative" {
		e.Test = s.RunNegative
	}
	return e.Run(ctx, os.Args[1])
}

func printSummary(parent, outcomes string) error {
	files, err := filepath.Glob(filepath.Join(parent, "run-*", "case-results.json"))
	if err != nil {
		return err
	}
	var latest *suite.Report
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		var r suite.Report
		if err = json.Unmarshal(data, &r); err != nil {
			return err
		}
		if latest == nil || r.Started.After(latest.Started) {
			r.Dir = filepath.Dir(file)
			latest = &r
		}
	}
	if latest == nil {
		return errors.New("required case report is missing")
	}
	if outcomes != "" {
		if latest.Finished.IsZero() {
			latest.RunError = "CI execution did not finalize the suite; " + outcomes
			latest.Finished = time.Now().UTC()
		}
		if strings.Contains(outcomes, "failure") || strings.Contains(outcomes, "cancelled") {
			latest.RunError = strings.TrimSpace(latest.RunError + "; CI phases: " + outcomes)
		}
		if err := latest.Save(); err != nil {
			return err
		}
	}
	if _, err = fmt.Print(latest.Markdown()); err != nil {
		return err
	}
	if !latest.Accepted() {
		if latest.NegativeControlConfirmed() {
			_, err := fmt.Println("\n**Detector control confirmed:** the deliberate violation was detected with a nonzero command exit, and isolation was restored. This is not a security acceptance pass.")
			return err
		}
		return errors.New("reported network acceptance failed")
	}
	return nil
}

func checkOutputPaths(state, artifacts string) error {
	for _, paths := range [][2]string{{state, artifacts}, {artifacts, state}} {
		if rel, err := filepath.Rel(paths[0], paths[1]); err != nil || filepath.IsLocal(rel) {
			return errors.New("artifacts and private state directories must not contain each other")
		}
	}
	return nil
}
