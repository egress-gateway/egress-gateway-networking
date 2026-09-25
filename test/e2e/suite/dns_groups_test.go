package suite

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cucumber/godog"
)

func TestDNSLaneInventory(t *testing.T) {
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	ts := godog.TestSuite{Options: &godog.Options{Paths: []string{filepath.Join(root, "test/e2e/features")}, Tags: "@dns"}}
	features, err := ts.RetrieveFeatures()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range features {
		for _, p := range f.Pickles {
			matches := 0
			for _, tag := range p.Tags {
				for _, lane := range dnsLanes {
					if tag.Name == "@dns-lane-"+lane {
						matches++
					}
				}
			}
			if matches != 1 {
				t.Errorf("%s has %d lanes", p.Name, matches)
			}
			count++
		}
	}
	if count != 64 {
		t.Fatalf("DNS coverage changed: %d", count)
	}
	s := &Suite{Root: root, Report: &Report{Profile: "calico-istio"}}
	for _, tags := range []string{"", "@dns", "@dns,@dns-egress,@pr0", "@dns-functional", "@dns-bypass,@dns-lifecycle"} {
		total, err := s.selected(tags)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := s.selected(andTags(tags, "~@dns"))
		if err != nil {
			t.Fatal(err)
		}
		for _, lane := range dnsLanes {
			n, err := s.selected(andTags(tags, "@dns-lane-"+lane))
			if err != nil {
				t.Fatal(err)
			}
			actual += n
		}
		if actual != total {
			t.Errorf("%s: partitions %d, inventory %d", tags, actual, total)
		}
	}
}

func TestConcurrentDNSReport(t *testing.T) {
	r := &Report{Mode: "enforce", Dir: t.TempDir()}
	for i := range 12 {
		r.Cases = append(r.Cases, CaseResult{ID: fmt.Sprint(i), Actual: NotRun})
	}
	var ops []func(context.Context) error
	for i := range 12 {
		ops = append(ops, func(context.Context) error {
			id := fmt.Sprint(i)
			if err := r.Update(func(r *Report) {
				r.Cases[i].Functionality = "satisfied"
				r.Cases[i].Phases = []PhaseTiming{{Name: "probe", Seconds: 1}}
			}); err != nil {
				return err
			}
			r.AddOperation(OperationTiming{Script: id})
			return r.Record(id, Satisfied, "", id+"/", time.Second)
		})
	}
	if err := dnsParallel(t.Context(), ops...); err != nil {
		t.Fatal(err)
	}
	if len(r.Operations) != 12 {
		t.Fatalf("lost operations: %d", len(r.Operations))
	}
	for _, c := range r.Results() {
		if c.Actual != Satisfied || len(c.Phases) != 1 {
			t.Fatalf("lost case %s", c.ID)
		}
	}
	if err := r.Record("0", Satisfied, "", "0/", time.Second); err == nil {
		t.Fatal("duplicate accepted")
	}
}
