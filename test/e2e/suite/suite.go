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
}

func (s *Suite) Run(ctx context.Context) error {
	var id, dir string
	var client, server access
	scenarios := 0
	suite := godog.TestSuite{
		Name:    "networking",
		Options: &godog.Options{Format: "pretty,junit:" + filepath.Join(s.Artifacts, "junit.xml"), Paths: []string{filepath.Join(s.Root, "test/e2e/features")}, Strict: true, Concurrency: 1},
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			sc.Before(func(_ context.Context, _ *godog.Scenario) (context.Context, error) {
				id = strings.ToLower(rand.Text()[:20])
				dir = filepath.Join(s.Artifacts, id)
				scenarios++
				client, server = access{}, access{}
				return ctx, os.MkdirAll(dir, 0o700)
			})
			operation := func(script string) error {
				return s.Execute(ctx, "test/e2e/scripts/"+script+".sh", "--state-dir", s.State, "--artifacts", dir, "--test-id", id)
			}
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
	if code != 0 {
		return fmt.Errorf("BDD suite exited %d", code)
	}
	if scenarios == 0 {
		return errors.New("no acceptance scenarios executed")
	}
	return nil
}
