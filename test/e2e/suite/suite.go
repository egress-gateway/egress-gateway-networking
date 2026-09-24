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
	dnsLane                string
}

func (s *Suite) Run(ctx context.Context) error {
	if s.Tags != "" {
		return s.runGrouped(ctx, s.Tags)
	}
	if s.Report != nil && s.Report.Profile == "calico-istio" {
		pendingNP := false
		for _, c := range s.Report.Results() {
			if strings.HasPrefix(c.ID, "NP-") && c.Actual == NotRun {
				pendingNP = true
			}
		}
		if pendingNP {
			if err := s.RunPolicy(ctx); err != nil {
				return err
			}
		}
		return s.runGrouped(ctx, "~@np")
	}
	return s.run(ctx, "~@calico")
}

func (s *Suite) RunPolicy(ctx context.Context) error {
	if err := s.run(ctx, "@np"); err != nil {
		return err
	}
	for _, c := range s.Report.Results() {
		if strings.HasPrefix(c.ID, "NP-") && !s.Report.CaseAccepted(c) {
			return fmt.Errorf("NP acceptance failed: %s: %s", c.ID, c.Reason)
		}
	}
	return nil
}

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
		if s.Report.Mode == "baseline" && (s.Report.BaselineInputs == "" || s.Report.BaselineInputs != receipt.Inputs) {
			return errors.New("reviewed baseline inputs missing or changed; investigate with enforce before explicitly updating expectations")
		}
	}
	var id, dir string
	var client, server access
	var currentCase, observed, reason string
	var blocked bool
	var egressPrepared, networkFault bool
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
				egressPrepared, networkFault = false, false
				egressExpected = egressInputs{}
				caseStarted = time.Now()
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
				if egressPrepared {
					cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 90*time.Second)
					stepErr = errors.Join(stepErr, s.Execute(cleanupCtx, "test/e2e/scripts/egress-cleanup.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id))
					cancel()
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
						return ctx, fmt.Errorf("%s: security=%s baseline=%s: %s", currentCase, observed, c.Expected, reason)
					}
				}
				return ctx, stepErr
			})
			operation := func(script string) error {
				return s.Execute(ctx, "test/e2e/scripts/"+script+".sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id)
			}
			sc.Step(`^the isolated local DNS configuration is ready$`, func() error {
				return s.Execute(ctx, "test/e2e/scripts/dns-up.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id, "--dns-lane", s.dnsLane)
			})
			sc.Step(`^the DNS operation "([^"]+)" uses "([^"]+)" and "([^"]+)"$`, func(mode, transport, qtype string) error {
				networkFault = dnsNeedsRecovery(mode)
				return s.runDNS(ctx, dir, id, currentCase, mode, transport, qtype)
			})
			sc.Step(`^local DNS functionality and isolation have independently correlated evidence$`, func() error {
				var functionality string
				var err error
				observed, functionality, reason, err = evaluateDNS(dir, id)
				if s.Report != nil {
					err = errors.Join(err, s.Report.Update(func(r *Report) {
						for i := range r.Cases {
							if r.Cases[i].ID == currentCase {
								r.Cases[i].Functionality = functionality
							}
						}
					}))
				}
				return err
			})
			sc.Step(`^the network probe "([^"]+)" targets "([^"]+)" during "([^"]+)"$`, func(protocol, target, phase string) error {
				egressExpected = egressInputs{Protocol: protocol, Target: target, Phase: phase}
				networkFault = phase != "healthy" && phase != "capture"
				return s.Execute(ctx, "test/e2e/scripts/network-case.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id, "--protocol", protocol, "--target", target, "--phase", phase)
			})
			sc.Step(`^the network contract "([^"]+)" has attributable packet and enforcement evidence$`, func(contract string) error {
				var err error
				if contract == "capture" || contract == "gateway" || contract == "chain" {
					observed, reason, err = awaitEvidence(ctx, 10*time.Second, func() (string, string, error) { return evaluateNetwork(dir, id, contract, egressExpected) }, func(ctx context.Context) error {
						script := "test/e2e/scripts/network-logs.sh"
						if contract == "chain" {
							script = "test/e2e/scripts/egress-logs.sh"
						}
						return s.Execute(ctx, script, "--state-dir", s.State, "--artifacts", dir, "--test-id", id)
					})
				} else {
					observed, reason, err = evaluateNetwork(dir, id, contract, egressExpected)
				}
				if observed == ExecutionError && egressExpected.Phase != "healthy" && egressExpected.Phase != "capture" {
					err = errors.Join(err, os.WriteFile(filepath.Join(s.State, "fault-active"), []byte(id+"\n"), 0600))
				}
				return err
			})
			sc.Step(`^the "([^"]+)" probe targets "([^"]+)" from "([^"]+)" during "([^"]+)"$`, func(protocol, target, source, phase string) error {
				egressExpected = egressInputs{Protocol: protocol, Target: target, Client: source, Phase: phase}
				if s.Report != nil && capturedEgressDNS(s.Report.Profile, egressExpected) {
					if err := operation("dns-up"); err != nil {
						return err
					}
					return s.runDNS(ctx, dir, id, currentCase, "egress-external", "udp", "A")
				}
				err := s.Execute(ctx, "test/e2e/scripts/egress-case.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id, "--protocol", protocol, "--target", target, "--client", source, "--phase", phase, "--defer-cleanup")
				egressPrepared = err == nil
				return err
			})
			sc.Step(`^the egress contract "([^"]+)" is evaluated using complete evidence for this case$`, func(contract string) error {
				var err error
				if s.Report != nil && capturedEgressDNS(s.Report.Profile, egressExpected) {
					if contract != "deny" {
						return errors.New("captured external DNS requires the denial contract")
					}
					observed, _, reason, err = evaluateDNS(dir, id)
					return err
				}
				observed, reason, err = awaitEvidence(ctx, 10*time.Second, func() (string, string, error) { return evaluateEgress(dir, id, contract, egressExpected) }, func(ctx context.Context) error {
					return s.Execute(ctx, "test/e2e/scripts/egress-logs.sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id)
				})
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
	if s.dnsLane != "" {
		out, err := s.dnsOutput()
		if err != nil {
			return err
		}
		defer out.Close()
		suite.Options.Output = out
	}
	code := suite.Run()
	if err := errors.Join(reportErrors...); err != nil {
		return err
	}
	if code != 0 {
		complete := s.Report != nil
		if s.Report != nil {
			for _, c := range s.Report.Results() {
				if tags == "@np" && !strings.HasPrefix(c.ID, "NP-") {
					continue
				}
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
