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
		return fmt.Errorf("usage: networking-e2e e2e|up|test|down [flags]")
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	state := flags.String("state-dir", ".e2e/state", "private retained state")
	artifacts := flags.String("artifacts", ".e2e/artifacts", "safe diagnostic output parent")
	cluster := flags.String("cluster", "", "new cluster name (networking-e2e- prefix)")
	keep := flags.Bool("keep", false, "retain the environment after e2e, including failures")
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
	ctx, cancel := context.WithTimeout(ctx, 25*time.Minute)
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
	defer func() {
		status := "passed"
		if result != nil {
			status = "failed"
		}
		data, _ := json.MarshalIndent(map[string]any{"command": os.Args[1], "sha": sha, "dirty": dirty != "", "go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH, "started": started, "finished": time.Now().UTC(), "result": status}, "", "  ")
		if err := os.WriteFile(filepath.Join(runDir, "run.json"), data, 0o600); err != nil {
			result = errors.Join(result, err)
		}
	}()
	execute := func(ctx context.Context, script string, args ...string) error {
		fmt.Printf("\n> %s\n", script)
		log, err := os.OpenFile(filepath.Join(runDir, strings.ReplaceAll(script, "/", "_")+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer log.Close()
		cmd := exec.CommandContext(ctx, bash, append([]string{filepath.Join(*root, script)}, args...)...)
		cmd.Dir = *root
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
	s := suite.Suite{Root: *root, State: *state, Artifacts: runDir, Execute: execute}
	e := environment.Environment{Root: *root, State: *state, Artifacts: runDir, Cluster: *cluster, Keep: *keep, Execute: execute, Test: s.Run}
	return e.Run(ctx, os.Args[1])
}

func checkOutputPaths(state, artifacts string) error {
	for _, paths := range [][2]string{{state, artifacts}, {artifacts, state}} {
		if rel, err := filepath.Rel(paths[0], paths[1]); err != nil || filepath.IsLocal(rel) {
			return errors.New("artifacts and private state directories must not contain each other")
		}
	}
	return nil
}
