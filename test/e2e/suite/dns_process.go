package suite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type dnsJob struct {
	cmd    *exec.Cmd
	done   chan struct{}
	err    error
	output *os.File
	stderr *os.File
}

func startDNSJob(ctx context.Context, dir, output, name string, args ...string) (*dnsJob, error) {
	out, err := os.OpenFile(filepath.Join(dir, output), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	e, err := os.OpenFile(filepath.Join(dir, output+".err"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		out.Close()
		return nil, err
	}
	c := exec.CommandContext(ctx, name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGTERM) }
	c.WaitDelay = 3 * time.Second
	c.Stdout = out
	c.Stderr = e
	if err = c.Start(); err != nil {
		out.Close()
		e.Close()
		return nil, err
	}
	j := &dnsJob{cmd: c, done: make(chan struct{}), output: out, stderr: e}
	go func() { j.err = errors.Join(c.Wait(), out.Close(), e.Close()); close(j.done) }()
	return j, nil
}
func (j *dnsJob) wait(ctx context.Context) error {
	select {
	case <-j.done:
		return j.err
	case <-ctx.Done():
		_ = syscall.Kill(-j.cmd.Process.Pid, syscall.SIGKILL)
		<-j.done
		return errors.Join(ctx.Err(), j.err)
	}
}

func dnsParallel(ctx context.Context, operations ...func(context.Context) error) error {
	results := make([]error, len(operations))
	var wg sync.WaitGroup
	for i, op := range operations {
		wg.Go(func() { results[i] = op(ctx) })
	}
	wg.Wait()
	return errors.Join(results...)
}

func dnsPoll(ctx context.Context, limit time.Duration, check func(context.Context) (bool, error)) error {
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready, err := check(ctx)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type dnsObserver struct {
	name string
	args []string
	stop []string
	job  *dnsJob
}

func (r *dnsRunner) observer(name, kind, address string, port int) *dnsObserver {
	stop := fmt.Sprintf("/dns-%s-%s-stop", r.id, name)
	args := []string{"exec", r.discovery.Cluster + "-control-plane"}
	switch kind {
	case "external":
		args = []string{"exec", r.discovery.Cluster + "-origin", "/probe"}
	case "capture":
		args = append(args, "nsenter", "-t", address, "-n", "/networking-probe")
	case "drops":
		args = append(args, "/networking-probe")
	}
	if kind == "drops" {
		args = append(args, "drops", "--target", address)
	} else {
		args = append(args, "capture", "--interface", "eth0", "--port", fmt.Sprint(port))
	}
	args = append(args, "--stop-file", stop)
	return &dnsObserver{name: name, args: args, stop: append(append([]string{}, args...), "--stop")}
}
func (r *dnsRunner) startObservers(ctx context.Context, obs ...*dnsObserver) error {
	// Register before launch so partial failure still visits every started process.
	r.observers = append(r.observers, obs...)
	ops := make([]func(context.Context) error, 0, len(obs))
	for _, o := range obs {
		ops = append(ops, func(ctx context.Context) error {
			var err error
			o.job, err = startDNSJob(r.observerContext, r.dir, o.name+".jsonl", "docker", o.args...)
			if err != nil {
				return err
			}
			return dnsPoll(ctx, 15*time.Second, func(context.Context) (bool, error) {
				select {
				case <-o.job.done:
					return false, fmt.Errorf("observer %s exited before ready: %w", o.name, errors.Join(o.job.err, errors.New("unexpected observer exit")))
				default:
				}
				b, err := os.ReadFile(filepath.Join(r.dir, o.name+".jsonl"))
				if err != nil {
					return false, err
				}
				for line := range strings.SplitSeq(string(b), "\n") {
					var p probeRecord
					if json.Unmarshal([]byte(line), &p) == nil && (p.Event == "capture-ready" || p.Event == "drops-ready") {
						return true, nil
					}
				}
				return false, nil
			})
		})
	}
	return dnsParallel(ctx, ops...)
}
func (r *dnsRunner) stopObservers(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	obs := r.observers
	r.observers = nil
	ops := make([]func(context.Context) error, 0, len(obs))
	for _, o := range obs {
		if o.job == nil {
			continue
		}
		ops = append(ops, func(ctx context.Context) error {
			_, signalErr := r.command(ctx, "docker", o.stop...)
			waitErr := o.job.wait(ctx)
			if signalErr != nil || waitErr != nil {
				return errors.Join(signalErr, waitErr)
			}
			ps, err := records(filepath.Join(r.dir, o.name+".jsonl"))
			if err != nil {
				return err
			}
			if strings.HasPrefix(o.name, "drops-") {
				for _, p := range ps {
					if p.Event == "drops-complete" {
						return nil
					}
				}
				return errors.New("missing drop completion")
			}
			return completeCapture(ps)
		})
	}
	return dnsParallel(ctx, ops...)
}
func (r *dnsRunner) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.WaitDelay = 3 * time.Second
	var stderr strings.Builder
	c.Stderr = &stderr
	b, err := c.Output()
	if err != nil {
		return b, fmt.Errorf("%s: %w: %s", name, err, stderr.String())
	}
	return b, nil
}
func (r *dnsRunner) saveCommand(ctx context.Context, file, name string, args ...string) error {
	j, err := startDNSJob(ctx, r.dir, file, name, args...)
	if err != nil {
		return err
	}
	return j.wait(ctx)
}
func (r *dnsRunner) write(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.dir, name), b, 0600)
}
func (r *dnsRunner) kubectl(args ...string) []string {
	return append([]string{"--kubeconfig", filepath.Join(r.s.State, "kubeconfig"), "--context", "kind-" + r.discovery.Cluster, "--request-timeout=10s"}, args...)
}
func (r *dnsRunner) k(ctx context.Context, args ...string) ([]byte, error) {
	return r.command(ctx, "kubectl", r.kubectl(args...)...)
}
func (r *dnsRunner) saveK(ctx context.Context, file string, args ...string) error {
	return r.saveCommand(ctx, file, "kubectl", r.kubectl(args...)...)
}
func (r *dnsRunner) apply(ctx context.Context, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c := exec.CommandContext(ctx, "kubectl", r.kubectl("apply", "-f", "-")...)
	c.Stdin = strings.NewReader(string(b))
	c.Stdout = io.Discard
	var e strings.Builder
	c.Stderr = &e
	c.WaitDelay = 3 * time.Second
	if err = c.Run(); err != nil {
		return fmt.Errorf("apply: %w: %s", err, e.String())
	}
	return nil
}

func dnsCleanup(ctx context.Context, stopBudget time.Duration, stop, restore func(context.Context) error) error {
	stopCtx, cancelStop := context.WithTimeout(context.WithoutCancel(ctx), stopBudget)
	stopErr := stop(stopCtx)
	cancelStop()
	restoreCtx, cancelRestore := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
	defer cancelRestore()
	return errors.Join(stopErr, restore(restoreCtx))
}
