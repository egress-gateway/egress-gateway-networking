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

	"github.com/cucumber/godog"
	"github.com/egress-gateway/egress-gateway-networking/test/e2e/environment"
)

type Suite struct {
	Root, State, Artifacts string
	Execute                environment.Executor
	Report                 *Report
}

func (s *Suite) Run(ctx context.Context) error {
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
		s.Report.InputDigest = receipt.Inputs
		if s.Report.Mode == "baseline" && (s.Report.BaselineInputs == "" || s.Report.BaselineInputs != receipt.Inputs) {
			return errors.New("reviewed baseline inputs missing or changed; investigate with enforce before explicitly updating expectations")
		}
	}
	var id, dir string
	var client, server access
	var currentCase, observed, reason string
	var blocked bool
	scenarios := 0
	var reportErrors []error
	suite := godog.TestSuite{
		Name:    "networking",
		Options: &godog.Options{Format: "pretty", Paths: []string{filepath.Join(s.Root, "test/e2e/features")}, Strict: true, Concurrency: 1},
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
				id = strings.ToLower(rand.Text()[:20])
				dir = filepath.Join(s.Artifacts, currentCase)
				scenarios++
				client, server = access{}, access{}
				return ctx, os.MkdirAll(dir, 0o700)
			})
			sc.After(func(ctx context.Context, _ *godog.Scenario, stepErr error) (context.Context, error) {
				if blocked {
					return ctx, stepErr
				}
				if stepErr != nil {
					observed, reason = ExecutionError, stepErr.Error()
				}
				if observed == "" {
					observed = Satisfied
				}
				if s.Report == nil {
					return ctx, stepErr
				}
				if err := s.Report.Record(currentCase, observed, reason, currentCase+"/"); err != nil {
					reportErrors = append(reportErrors, err)
					return ctx, err
				}
				for _, c := range s.Report.Cases {
					if c.ID == currentCase && !s.Report.CaseAccepted(c) {
						return ctx, fmt.Errorf("%s: security=%s baseline=%s: %s", currentCase, observed, c.Expected, reason)
					}
				}
				return ctx, stepErr
			})
			operation := func(script string) error {
				return s.Execute(ctx, "test/e2e/scripts/"+script+".sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id)
			}
			sc.Step(`^the "([^"]+)" probe targets "([^"]+)" from "([^"]+)" during "([^"]+)"$`, func(protocol, target, source, phase string) error {
				return s.Execute(ctx, "test/e2e/scripts/egress-case.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id, "--protocol", protocol, "--target", target, "--client", source, "--phase", phase)
			})
			sc.Step(`^the egress contract "([^"]+)" is evaluated$`, func(contract string) error {
				var err error
				observed, reason, err = evaluateEgress(dir, id, contract)
				return err
			})
			sc.Step(`^the shared Istio installation and test workloads are ready$`, func() error { return ctx.Err() })
			sc.Step(`^native injection validates CNI redirection without istio-init$`, func() error { return operation("verify") })
			sc.Step(`^the meshed client requests httpbin without an application proxy$`, func() error { return operation("request") })
			sc.Step(`^httpbin echoes this request's correlation ID$`, func() error {
				data, err := os.ReadFile(filepath.Join(dir, "response.json"))
				if err != nil {
					return err
				}
				var body struct {
					Headers map[string][]string `json:"headers"`
				}
				if err = json.Unmarshal(data, &body); err != nil {
					return err
				}
				for key, values := range body.Headers {
					if strings.EqualFold(key, "X-Networking-Test-Id") && len(values) == 1 && values[0] == id {
						return nil
					}
				}
				return errors.New("httpbin did not echo this request's correlation header")
			})
			sc.Step(`^both proxies record this HTTP request$`, func() error {
				for name, dst := range map[string]*access{"client.log": &client, "server.log": &server} {
					file, err := os.Open(filepath.Join(dir, name))
					if err != nil {
						return err
					}
					*dst, err = findAccess(file, id)
					_ = file.Close()
					if err != nil {
						return fmt.Errorf("%s: %w", name, err)
					}
				}
				if client.Cluster != serviceCluster {
					return fmt.Errorf("unexpected client upstream %q", client.Cluster)
				}
				return nil
			})
			sc.Step(`^this request uses TLS with the expected peer SPIFFE identities on both sides$`, func() error { return checkMTLS(client, server) })
			sc.Step(`^a temporary client without a sidecar requests httpbin in plaintext$`, func() error { return operation("plaintext") })
			sc.Step(`^it receives no HTTP response and the server records a TLS listener rejection$`, func() error { return plaintextEvidence(dir) })
		},
	}
	code := suite.Run()
	if err := errors.Join(reportErrors...); err != nil {
		return err
	}
	if code != 0 {
		complete := s.Report != nil
		if s.Report != nil {
			for _, c := range s.Report.Cases {
				complete = complete && c.Actual != NotRun
			}
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
