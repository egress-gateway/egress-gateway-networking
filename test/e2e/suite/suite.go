// Package suite binds observable Gherkin behavior to complete shell operations.
package suite

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/egress-gateway/egress-gateway-networking/test/e2e/environment"
)

type Suite struct {
	Root, State, Artifacts string
	Execute                environment.Executor
	Report                 *Report
	Tags                   string
}

func (s *Suite) Run(ctx context.Context) error { return s.run(ctx, s.Tags) }

func (s *Suite) run(ctx context.Context, tags string) error {
	if s.Report != nil {
		tags = profileTags(s.Report.Profile, tags)
	}
	if s.Report != nil {
		data, err := os.ReadFile(filepath.Join(s.State, "environment.json"))
		if err != nil {
			return err
		}
		var receipt struct {
			Inputs string `json:"inputs"`
		}
		if err = json.Unmarshal(data, &receipt); err != nil {
			return err
		}
		if err := s.Report.Update(func(r *Report) { r.InputDigest = receipt.Inputs }); err != nil {
			return err
		}
	}
	var id, dir string
	var currentCase, observed, reason string
	var blocked bool
	var networkFault bool
	var egressExpected egressInputs
	var caseStarted time.Time
	scenarios := 0
	var reportErrors []error
	suite := godog.TestSuite{
		Name:    "networking",
		Options: &godog.Options{Format: "pretty", Paths: []string{filepath.Join(s.Root, "test/e2e/features")}, Strict: true, Concurrency: 1, Tags: tags},
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			sc.Before(func(_ context.Context, scenario *godog.Scenario) (context.Context, error) {
				blocked = ctx.Err() != nil
				if _, err := os.Stat(filepath.Join(s.State, "fault-active")); err == nil {
					blocked = true
				}
				if blocked {
					return ctx, errors.New("suite interrupted or previous fault was not restored")
				}
				currentCase, observed, reason = caseID(scenario.Name), "", ""
				networkFault = false
				egressExpected = egressInputs{}
				caseStarted = time.Now()
				id = strings.ToLower(rand.Text()[:20])
				dir = filepath.Join(s.Artifacts, currentCase)
				scenarios++
				return ctx, os.MkdirAll(dir, 0o700)
			})
			sc.After(func(ctx context.Context, _ *godog.Scenario, stepErr error) (context.Context, error) {
				if blocked {
					return ctx, stepErr
				}
				if stepErr != nil {
					observed, reason = ExecutionError, stepErr.Error()
				}
				if networkFault && (stepErr != nil || observed == ExecutionError || observed == Inconclusive) {
					stepErr = errors.Join(stepErr, os.WriteFile(filepath.Join(s.State, "fault-active"), []byte(id+"\n"), 0600))
				}
				if observed == "" {
					observed = Satisfied
				}
				if s.Report == nil {
					return ctx, stepErr
				}
				if err := s.Report.Record(currentCase, observed, reason, currentCase+"/", time.Since(caseStarted)); err != nil {
					reportErrors = append(reportErrors, err)
					return ctx, err
				}
				for _, c := range s.Report.Results() {
					if c.ID == currentCase && !s.Report.CaseAccepted(c) {
						return ctx, fmt.Errorf("%s: security=%s expected=%s: %s", currentCase, observed, c.Expected, reason)
					}
				}
				return ctx, stepErr
			})
			operation := func(script string) error {
				return s.Execute(ctx, "test/e2e/scripts/"+script+".sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id)
			}
			sc.Step(`^the independent enrollment bindings are ready$`, func() error { return operation("enrollment-up") })
			sc.Step(`^the fixed Istio CNI combination is exercised with trusted network preparation$`, func() error {
				networkFault = true
				return operation("cni-integration")
			})
			sc.Step(`^combination startup, IPv6, denial and recovery have attributable evidence$`, func() error {
				var err error
				observed, reason, err = evaluateIntegration(dir, id)
				return err
			})

			sc.Step(`^restricted components cannot acquire identity or network privileges$`, func() error {
				if err := operation("enrollment-privileges"); err != nil {
					return err
				}
				return checkPrivileges(dir, id)
			})

			sc.Step(`^the network probe "([^"]+)" targets "([^"]+)" during "([^"]+)"$`, func(protocol, target, phase string) error {
				egressExpected = egressInputs{Protocol: protocol, Target: target, Phase: phase}
				networkFault = phase != "healthy"
				return s.Execute(ctx, "test/e2e/scripts/network-case.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id, "--protocol", protocol, "--target", target, "--phase", phase)
			})
			sc.Step(`^the network contract "([^"]+)" has attributable packet and enforcement evidence$`, func(contract string) error {
				var err error
				observed, reason, err = evaluateNetwork(dir, id, contract, egressExpected)

				if observed == ExecutionError && egressExpected.Phase != "healthy" {
					err = errors.Join(err, os.WriteFile(filepath.Join(s.State, "fault-active"), []byte(id+"\n"), 0600))
				}
				return err
			})
		},
	}
	code := suite.Run()
	if err := errors.Join(reportErrors...); err != nil {
		return err
	}
	if code != 0 {
		complete := s.Report != nil
		if s.Report != nil {
			features, err := suite.RetrieveFeatures()
			if err != nil {
				return err
			}
			pending := make(map[string]bool)
			for _, feature := range features {
				for _, scenario := range feature.Pickles {
					pending[caseID(scenario.Name)] = true
				}
			}
			for _, c := range s.Report.Results() {
				if c.Actual != NotRun {
					delete(pending, c.ID)
				}
			}
			complete = len(pending) == 0
		}
		if !complete {
			return fmt.Errorf("BDD suite exited %d before every case was recorded", code)
		}
		// Case verdicts, including enforcement failures, are finalized by the
		// report. Only an incomplete execution is a separate lifecycle error.
	}
	if scenarios == 0 {
		return errors.New("no acceptance scenarios executed")
	}
	return nil
}
