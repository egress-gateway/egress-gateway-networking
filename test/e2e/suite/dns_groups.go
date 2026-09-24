package suite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

var dnsLanes = []string{"records", "destinations", "bypass", "lifecycle"}

func (s *Suite) dnsNamespace() string { return "networking-" + s.dnsState() }
func (s *Suite) dnsState() string {
	if s.dnsLane == "" {
		return "dns"
	}
	return "dns-" + s.dnsLane
}

func andTags(tags, term string) string {
	if tags == "" {
		return term
	}
	clauses := strings.Split(tags, ",")
	for i := range clauses {
		clauses[i] += " && " + term
	}
	return strings.Join(clauses, ",")
}

func (s *Suite) selected(tags string) (int, error) {
	if s.Report != nil {
		tags = profileTags(s.Report.Profile, tags)
	}
	ts := godog.TestSuite{Options: &godog.Options{Paths: []string{filepath.Join(s.Root, "test/e2e/features")}, Tags: tags}}
	features, err := ts.RetrieveFeatures()
	n := 0
	for _, f := range features {
		n += len(f.Pickles)
	}
	return n, err
}

// Only DNS groups overlap. Node, primary CNI, gateway and Istiod faults finish
// before these private namespace-local fixtures start.
func (s *Suite) runGrouped(ctx context.Context, tags string) error {
	if s.Report == nil || s.Report.Profile != "calico-istio" {
		return s.run(ctx, tags)
	}
	total, err := s.selected(tags)
	if err != nil {
		return err
	}
	if total == 0 {
		return errors.New("no acceptance scenarios selected")
	}
	serial := andTags(tags, "~@dns")
	n, err := s.selected(serial)
	if err != nil {
		return err
	}
	var ops []func(context.Context) error
	covered := n
	for _, lane := range dnsLanes {
		selection := andTags(tags, "@dns-lane-"+lane)
		count, err := s.selected(selection)
		if err != nil {
			return err
		}
		covered += count
		if count == 0 {
			continue
		}
		child := *s
		child.dnsLane = lane
		ops = append(ops, func(ctx context.Context) error {
			start := time.Now()
			err := child.run(ctx, selection)
			op := OperationTiming{Script: "dns-group/" + lane, Started: start, Seconds: time.Since(start).Seconds()}
			if err != nil {
				op.Error = err.Error()
			}
			s.Report.AddOperation(op)
			return err
		})
	}
	if covered != total {
		return fmt.Errorf("DNS group coverage %d does not match selected inventory %d", covered, total)
	}
	if n > 0 {
		if err := s.run(ctx, serial); err != nil {
			return err
		}
	}
	return dnsParallel(ctx, ops...)
}

func (s *Suite) dnsOutput() (*os.File, error) {
	return os.OpenFile(filepath.Join(s.Artifacts, "dns-group-"+s.dnsLane+".log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
}
