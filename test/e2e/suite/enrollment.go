package suite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (s *Suite) enrollmentOperation(ctx context.Context, dir, id, mode string) (result error) {
	args := []string{"--state-dir", s.State, "--artifacts", dir, "--test-id", id, "--phase", mode}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 75*time.Second)
		defer cancel()
		args[len(args)-1] = "cleanup"
		if err := s.Execute(cleanup, "test/e2e/scripts/enrollment-operation.sh", args...); err != nil {
			result = fmt.Errorf("enrollment cleanup: %w (operation: %v)", err, result)
		}
	}()
	return s.Execute(ctx, "test/e2e/scripts/enrollment-operation.sh", args...)
}

type enrollmentPodEvidence struct {
	UID    string            `json:"uid"`
	Labels map[string]string `json:"labels"`
	Names  []string          `json:"names"`
	Init   []struct {
		Name             string `json:"name"`
		RestartPolicy    string `json:"restartPolicy"`
		Started          bool   `json:"started"`
		RestartCount     int    `json:"restartCount"`
		State, LastState map[string]json.RawMessage
	} `json:"init"`
	App []struct {
		Name             string
		Started          bool
		State, LastState map[string]json.RawMessage
		RestartCount     int
	} `json:"app"`
}

func evaluateEnrollment(dir, id, mode string) (string, string, error) {
	read := func(name string) (enrollmentPodEvidence, error) {
		var p enrollmentPodEvidence
		data, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err == nil {
			err = json.Unmarshal(data, &p)
		}
		if err == nil && p.UID == "" {
			err = fmt.Errorf("missing Pod identity")
		}
		return p, err
	}
	if mode == "privileges" {
		var p struct {
			ID                                             string
			UIDBefore, GIDBefore, UIDAfter, GIDAfter       int
			SetUIDDenied, SetGIDDenied, NetworkAdminDenied bool
		}
		data, err := os.ReadFile(filepath.Join(dir, "privileges.json"))
		if err != nil {
			return "", "", err
		}
		if err = json.Unmarshal(data, &p); err != nil {
			return "", "", err
		}
		if p.ID != id || p.UIDBefore != 10000 || p.GIDBefore != 10000 {
			return ExecutionError, "application privilege probe identity missing", nil
		}
		if p.UIDAfter != p.UIDBefore || p.GIDAfter != p.GIDBefore || !p.SetUIDDenied || !p.SetGIDDenied || !p.NetworkAdminDenied {
			return Violated, "application could change identity or exercise network administration", nil
		}
		return Satisfied, "application cannot adopt proxy UID/GID or perform network administration", nil
	}
	if mode == "injection" {
		a, err := read("enrolled")
		if err != nil {
			return "", "", err
		}
		b, err := read("ordinary")
		if err != nil {
			return "", "", err
		}
		count := func(p enrollmentPodEvidence) int {
			n := 0
			for _, s := range p.Names {
				if s == "istio-proxy" {
					n++
				}
			}
			for _, s := range p.Init {
				if s.Name == "istio-proxy" {
					n++
				}
			}
			return n
		}
		if a.Labels["networking.egress/enabled"] != "true" || b.Labels["networking.egress/enabled"] != "" || a.UID == b.UID {
			return ExecutionError, "incorrect original-label comparison", nil
		}
		native := false
		for _, i := range a.Init {
			native = native || i.Name == "istio-proxy" && i.RestartPolicy == "Always"
		}
		if count(a) != 1 || count(b) != 1 || !native {
			return Violated, "injection changed native sidecar or skipped ordinary Pod", nil
		}
		return Satisfied, "original-label enrollment has one native proxy; ordinary Pod in the same namespace still injects", nil
	}
	if mode != "startup" {
		return ExecutionError, "unsupported enrollment assertion", nil
	}
	p, err := read("startup")
	if err != nil {
		return "", "", err
	}
	exercised, marker := false, false
	for _, i := range p.Init {
		if i.Name == "istio-proxy" {
			exercised = i.RestartCount >= 1
			continue
		}
		if i.Name == "business-marker" {
			marker = true
			if i.Started || i.State["running"] != nil || i.State["terminated"] != nil || len(i.LastState) != 0 {
				return Violated, "business init ran before proxy startup succeeded", nil
			}
		}
	}
	if !exercised || !marker || len(p.App) == 0 {
		return Inconclusive, "missing exercised proxy failure or business container statuses", nil
	}
	for _, a := range p.App {
		if a.Started || a.State["running"] != nil || a.State["terminated"] != nil || len(a.LastState) != 0 {
			return Violated, "application ran before proxy startup succeeded", nil
		}
	}
	return Satisfied, "proxy startup failure caused restart while business init and application remained unstarted", nil
}

// A negative functional control uses the same raw-TCP evaluator as C1-01.
func (s *Suite) rejectMissingListener(ctx context.Context, dir, id string) (result error) {
	expected := egressInputs{Protocol: "tcp", Target: "mesh-external", Phase: "capture"}
	sample := func(ctx context.Context, name string) (string, string, error) {
		dst := filepath.Join(dir, name)
		if err := os.MkdirAll(dst, 0700); err != nil {
			return "", "", err
		}
		cid := id + "-" + name
		if err := s.Execute(ctx, "test/e2e/scripts/network-case.sh", "--state-dir", s.State, "--artifacts", dst, "--test-id", cid, "--protocol", "tcp", "--target", "mesh-external", "--phase", "capture"); err != nil {
			return "", "", err
		}
		return awaitEvidence(ctx, 10*time.Second, func() (string, string, error) { return evaluateNetwork(dst, cid, "capture", expected) }, func(ctx context.Context) error {
			return s.Execute(ctx, "test/e2e/scripts/network-logs.sh", "--state-dir", s.State, "--artifacts", dst, "--test-id", cid)
		})
	}
	transition := func(ctx context.Context, phase string) error {
		return s.Execute(ctx, "test/e2e/scripts/enrollment-operation.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id, "--phase", phase)
	}
	actual, reason, err := sample(ctx, "before")
	if err != nil || actual != Satisfied {
		return fmt.Errorf("listener control before fault: %s: %w", reason, errors.Join(err, errors.New(actual)))
	}
	if err = os.WriteFile(filepath.Join(s.State, "fault-active"), []byte(id), 0600); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
		defer cancel()
		err := transition(cleanup, "listener-restore")
		if err == nil {
			a, r, e := sample(cleanup, "after")
			if e != nil || a != Satisfied {
				err = fmt.Errorf("listener recovery: %s: %w", r, errors.Join(e, errors.New(a)))
			}
		}
		if err == nil {
			err = os.Remove(filepath.Join(s.State, "fault-active"))
		}
		result = errors.Join(result, err)
	}()
	if err = transition(ctx, "listener-remove"); err != nil {
		return err
	}
	actual, reason, err = sample(ctx, "missing")
	if err != nil || actual != Violated || reason != "required TCP redirect listener 15001 is absent" {
		return fmt.Errorf("missing listener not rejected by capture evaluator: %s: %w", reason, errors.Join(err, errors.New(actual)))
	}
	return nil
}

func brokenDNSVerdict(actual, functionality, reason string, err error) (string, string, error) {
	if err != nil {
		return actual, reason, err
	}
	if actual == Violated {
		return actual, reason, nil
	}
	if actual != Satisfied || functionality != "not_satisfied" {
		return actual, reason, fmt.Errorf("broken DNS must retain isolation but fail functionality: %s %s %s", actual, functionality, reason)
	}
	return Satisfied, "normal declared-name evaluator rejected broken DNS; isolation and functional recovery verified", nil
}
