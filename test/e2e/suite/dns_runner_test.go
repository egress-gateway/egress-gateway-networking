package suite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSParallelWaitsForEveryOperationOnFailure(t *testing.T) {
	var completed atomic.Int32
	err := dnsParallel(t.Context(), func(context.Context) error { return errors.New("failed receiver") }, func(context.Context) error { completed.Add(1); return nil })
	if err == nil || completed.Load() != 1 {
		t.Fatal("parallel failure skipped another result")
	}
}
func TestDNSPollDoesNotWaitAfterReady(t *testing.T) {
	calls := 0
	if err := dnsPoll(t.Context(), time.Hour, func(context.Context) (bool, error) { calls++; return true, nil }); err != nil || calls != 1 {
		t.Fatal(calls, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := dnsPoll(ctx, time.Hour, func(context.Context) (bool, error) { return false, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestDNSJobCancellationReapsProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	j, err := startDNSJob(ctx, t.TempDir(), "probe", "sh", "-c", "exec sleep 60")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	bounded, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err = j.wait(bounded); err == nil {
		t.Fatal("canceled command passed")
	}
	select {
	case <-j.done:
	default:
		t.Fatal("process was not reaped")
	}
}
func TestDNSObserverPartialStartAndStopFailuresStillReapAll(t *testing.T) {
	for _, failure := range []string{"none", "start", "stop"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			script := `#!/bin/sh
case "$*" in
 *--stop) case "$*" in *broken*) test "$FAIL_OBSERVER" != stop || exit 3;; esac
 touch "$DNS_TEST_STOP"; exit 0;;
esac
case "$*" in *broken*) test "$FAIL_OBSERVER" != start || exit 2;; esac
printf '{"event":"capture-ready"}\n'
while test ! -f "$DNS_TEST_STOP"; do sleep 0.02; done
printf '{"event":"capture-complete","dropped":0,"captured":0,"kernel_packets":0}\n'
`
			if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("FAIL_OBSERVER", failure)
			t.Setenv("DNS_TEST_STOP", filepath.Join(dir, "stop"))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r := &dnsRunner{dir: dir, id: "case", observerContext: ctx}
			a, b := r.observer("healthy", "capture", "1", 53), r.observer("broken", "capture", "2", 53)
			err := r.startObservers(ctx, a, b)
			if (err != nil) != (failure == "start") {
				t.Fatalf("start=%v", err)
			}
			clean, stop := context.WithTimeout(t.Context(), time.Second)
			defer stop()
			err = r.stopObservers(clean)
			if failure != "none" && err == nil {
				t.Fatal("observer failure hidden")
			}
			for _, o := range []*dnsObserver{a, b} {
				if o.job != nil {
					select {
					case <-o.job.done:
					default:
						t.Fatal("orphan observer")
					}
				}
			}
			if len(r.observers) != 0 {
				t.Fatal("completed observers retained")
			}
		})
	}
}
func TestDNSObserverReadinessPrecedesNextStage(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
printf '{"event":"capture-ready"}\n'
exec sleep 60
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithCancel(t.Context())
	r := &dnsRunner{dir: dir, id: "case", observerContext: ctx}
	obs := r.observer("receiver", "capture", "1", 53)
	if err := r.startObservers(ctx, obs); err != nil {
		cancel()
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "receiver.jsonl"))
	if err != nil || !strings.Contains(string(b), "capture-ready") {
		t.Fatal("next stage started without ready", err)
	}
	cancel()
	clean, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	_ = obs.job.wait(clean)
}
func TestDNSPhaseTimingPersistsFailure(t *testing.T) {
	dir := t.TempDir()
	r := &dnsRunner{s: &Suite{}, dir: dir}
	want := errors.New("receiver failed")
	if err := r.stage("health-before", func() error { return want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	var ps []PhaseTiming
	if err := readDNSJSON(dir, "dns-phases.json", &ps); err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Name != "health-before" || ps[0].Error != want.Error() || ps[0].Seconds < 0 {
		t.Fatal(ps)
	}
	r.dir = filepath.Join(dir, "missing")
	if err := r.stage("probe", func() error { return nil }); err == nil {
		t.Fatal("phase persistence failure hidden")
	}
}

func TestDNSFailedObserverCannotConsumeRecoveryBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	restored := false
	err := dnsCleanup(ctx, 10*time.Millisecond, func(stop context.Context) error {
		j, err := startDNSJob(context.WithoutCancel(ctx), t.TempDir(), "observer", "sh", "-c", "exec sleep 60")
		if err != nil {
			return err
		}
		// The stop command failed; the observer is still running until bounded reap.
		return errors.Join(errors.New("stop failed"), j.wait(stop))
	}, func(recovery context.Context) error {
		restored = true
		if recovery.Err() != nil {
			t.Fatal("recovery received expired context")
		}
		return nil
	})
	if err == nil || !restored || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("failed stop did not preserve independent recovery", restored, err)
	}
}
