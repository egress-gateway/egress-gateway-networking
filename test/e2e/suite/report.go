package suite

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	versions "github.com/egress-gateway/egress-gateway-networking/baseline"
)

const (
	Satisfied      = "satisfied"
	Violated       = "violated"
	ExecutionError = "execution_error"
	Inconclusive   = "inconclusive"
	NotRun         = "not_run"
)

type CaseResult struct {
	Phases                []PhaseTiming `json:"phases,omitempty"`
	FunctionalityRequired bool          `json:"functionality_required,omitzero"`
	Functionality         string        `json:"functionality,omitempty"`
	ID                    string        `json:"id"`
	Name                  string        `json:"name"`
	Requirement           string        `json:"requirement"`
	Expected              string        `json:"baseline_expected"`
	Actual                string        `json:"security_result"`
	Acceptance            string        `json:"acceptance"`
	Reason                string        `json:"reason,omitempty"`
	Evidence              string        `json:"evidence,omitempty"`
	DurationSeconds       float64       `json:"duration_seconds"`
}

type Report struct {
	mu             sync.Mutex
	Mode           string            `json:"acceptance_mode"`
	Profile        string            `json:"profile"`
	SHA            string            `json:"sha"`
	Dirty          bool              `json:"dirty"`
	RunID          string            `json:"run_id"`
	Started        time.Time         `json:"started"`
	Finished       time.Time         `json:"finished,omitzero"`
	BaselineInputs string            `json:"baseline_inputs,omitempty"`
	Configuration  map[string]string `json:"configuration,omitempty"`
	InputDigest    string            `json:"input_digest,omitempty"`
	RunError       string            `json:"run_error,omitempty"`
	Security       string            `json:"security_verdict"`
	Acceptance     string            `json:"acceptance"`
	Cases          []CaseResult      `json:"cases"`
	Operations     []OperationTiming `json:"operations,omitempty"`
	Dir            string            `json:"-"`
}

type OperationTiming struct {
	Script  string    `json:"script"`
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	Error   string    `json:"error,omitempty"`
}

func caseID(name string) string { id, _, _ := strings.Cut(name, " "); return id }

func NewReport(root, dir, mode, sha string, dirty bool) (*Report, error) {
	return NewProfileReport(root, dir, "istio-only", mode, sha, dirty)
}

func NewProfileReport(root, dir, profile, mode, sha string, dirty bool) (*Report, error) {
	if profile != "istio-only" && profile != "calico-istio" {
		return nil, fmt.Errorf("unknown profile %q", profile)
	}
	if profile == "calico-istio" && mode != "enforce" {
		return nil, errors.New("calico-istio requires enforce acceptance")
	}
	if mode != "baseline" && mode != "enforce" {
		return nil, fmt.Errorf("unknown acceptance mode %q", mode)
	}
	r := &Report{Mode: mode, Profile: profile, SHA: sha, Dirty: dirty, Dir: dir, RunID: filepath.Base(dir), Started: time.Now().UTC()}
	var baseline struct {
		Profile string            `json:"profile"`
		Inputs  string            `json:"inputs"`
		Cases   map[string]string `json:"cases"`
	}
	data, err := os.ReadFile(filepath.Join(root, "test/e2e/baselines/istio-only.json"))
	if err == nil {
		err = json.Unmarshal(data, &baseline)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if profile == "istio-only" && baseline.Profile != "" && baseline.Profile != r.Profile {
		return nil, errors.New("baseline profile mismatch")
	}
	r.BaselineInputs = baseline.Inputs
	r.Configuration = map[string]string{"topology": "single-node IPv4; kind default network; chained Istio CNI; sidecar + official gateway"}
	if profile == "calico-istio" {
		r.Configuration["topology"] = "single-node IPv4; Calico iptables/VXLAN; kube-proxy; chained Istio CNI; isolated NP fixture"
		r.Configuration["CALICO_VERSION"] = versions.Current().Calico["CALICO_VERSION"]
	}
	if run := os.Getenv("GITHUB_RUN_ID"); run != "" {
		r.Configuration["ci_run"] = run
		r.Configuration["ci_attempt"] = os.Getenv("GITHUB_RUN_ATTEMPT")
	}
	if versions, err := os.ReadFile(filepath.Join(root, "install/versions.env")); err == nil {
		for line := range strings.SplitSeq(string(versions), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok && (key == "KIND_VERSION" || key == "KIND_IMAGE" || key == "ISTIO_VERSION" || key == "HELM_VERSION") {
				r.Configuration[key] = value
			}
		}
	}
	tags := profileTags(profile, "")
	ts := godog.TestSuite{Options: &godog.Options{Paths: []string{filepath.Join(root, "test/e2e/features")}, Tags: tags}}
	features, err := ts.RetrieveFeatures()
	if err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	for _, feature := range features {
		for _, p := range feature.Pickles {
			id := caseID(p.Name)
			if !regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9]{2}$`).MatchString(id) || ids[id] {
				return nil, fmt.Errorf("invalid or duplicate case ID in %q", p.Name)
			}
			ids[id] = true
			requirement := strings.TrimPrefix(p.Name, id+" ")
			for _, step := range p.Steps {
				if rest, ok := strings.CutPrefix(step.Text, `the egress contract "`); ok {
					requirement, _, _ = strings.Cut(rest, `"`)
				}
			}
			required := false
			for _, tag := range p.Tags {
				required = required || tag.Name == "@dns-functional"
			}
			r.Cases = append(r.Cases, CaseResult{FunctionalityRequired: required, ID: id, Name: p.Name, Requirement: requirement, Expected: baseline.Cases[id], Actual: NotRun})
		}
	}
	if len(r.Cases) == 0 {
		return nil, errors.New("empty acceptance inventory")
	}
	for id := range baseline.Cases {
		if profile == "istio-only" && !ids[id] {
			return nil, fmt.Errorf("baseline contains removed case %s", id)
		}
	}
	return r, nil
}

func (r *Report) CaseAccepted(c CaseResult) bool {
	if c.FunctionalityRequired && c.Functionality != "satisfied" {
		return false
	}
	if (strings.HasPrefix(c.ID, "P0-") || c.Requirement == "allow" || c.Requirement == "gateway") && c.Actual != Satisfied {
		return false
	}
	if c.Actual != Satisfied && c.Actual != Violated {
		return false
	}
	if r.Mode == "enforce" {
		return c.Actual == Satisfied
	}
	return (c.Expected == Satisfied || c.Expected == Violated) && c.Actual == c.Expected
}

func (r *Report) Accepted() bool {
	if r.Finished.IsZero() || r.RunError != "" || len(r.Cases) == 0 {
		return false
	}
	for _, c := range r.Cases {
		if !r.CaseAccepted(c) {
			return false
		}
	}
	if r.Mode == "baseline" && r.Profile == "istio-only" {
		for _, c := range r.Cases {
			if c.Actual == Violated {
				return true
			}
		}
		return false
	}
	return true
}

func (r *Report) Record(id, actual, reason, evidence string, elapsed time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if actual != Satisfied && actual != Violated && actual != ExecutionError && actual != Inconclusive && actual != NotRun {
		return fmt.Errorf("invalid result %q", actual)
	}
	for i := range r.Cases {
		c := &r.Cases[i]
		if c.ID != id {
			continue
		}
		if c.Actual != NotRun || c.Evidence != "" {
			return fmt.Errorf("duplicate result for %s", id)
		}
		c.Actual, c.Reason, c.Evidence = actual, reason, evidence
		c.DurationSeconds = elapsed.Seconds()
		return r.save()
	}
	return fmt.Errorf("unknown case %s", id)
}

func (r *Report) Save() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.save()
}

func (r *Report) save() error {
	r.Security = "contract satisfied within tested profile"
	incomplete, violated := false, false
	for i := range r.Cases {
		c := &r.Cases[i]
		c.Acceptance = "FAIL"
		if r.CaseAccepted(*c) {
			c.Acceptance = "PASS"
		}
		violated = violated || c.Actual == Violated
		incomplete = incomplete || c.Actual != Satisfied && c.Actual != Violated
	}
	if incomplete || r.RunError != "" {
		r.Security = "incomplete evidence"
	}
	if violated {
		r.Security = "not fail-closed"
		if incomplete {
			r.Security += " (additional cases incomplete)"
		}
	}
	r.Acceptance = "FAIL"
	if r.Accepted() {
		r.Acceptance = "PASS"
	}
	if err := os.MkdirAll(r.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err = atomicReport(filepath.Join(r.Dir, "case-results.json"), append(data, '\n')); err != nil {
		return err
	}
	if err = atomicReport(filepath.Join(r.Dir, "summary.md"), []byte(r.Markdown())); err != nil {
		return err
	}
	return atomicReport(filepath.Join(r.Dir, "junit.xml"), r.junit())
}

func atomicReport(path string, data []byte) error {
	if err := os.WriteFile(path+".new", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}

func (r *Report) Markdown() string {
	escape := func(s string) string {
		return strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;").Replace(s)
	}
	icon := map[string]string{Satisfied: "✅", Violated: "❌", ExecutionError: "🛑", Inconclusive: "⚠️", NotRun: "⏸"}
	counts := map[string]int{}
	passed := 0
	var failed []string
	for _, c := range r.Cases {
		counts[c.Actual]++
		if r.CaseAccepted(c) {
			passed++
		} else {
			failed = append(failed, c.ID)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Networking E2E\n\n**Acceptance: %s (%s)** · **Security: %s**\n\nSHA: `%s` · dirty: `%t` · run: `%s` · profile: `%s` · inputs: `%s`\n\n", r.Acceptance, r.Mode, r.Security, r.SHA, r.Dirty, r.RunID, r.Profile, r.InputDigest)
	if r.Configuration["purpose"] != "" {
		fmt.Fprintf(&b, "**Purpose: %s**\n\n", escape(r.Configuration["purpose"]))
	}
	if r.Configuration["ci_run"] != "" {
		fmt.Fprintf(&b, "CI run: `%s` · attempt: `%s`\n\n", escape(r.Configuration["ci_run"]), escape(r.Configuration["ci_attempt"]))
	}
	fmt.Fprintf(&b, "Environment: %s · kind %s · Istio %s · node `%s`\n\n", escape(r.Configuration["topology"]), escape(r.Configuration["KIND_VERSION"]), escape(r.Configuration["ISTIO_VERSION"]), escape(r.Configuration["KIND_IMAGE"]))
	if r.Configuration["kernel"] != "" {
		fmt.Fprintf(&b, "Runtime: %s\n\n", escape(r.Configuration["kernel"]))
	}
	fmt.Fprintf(&b, "Cases: %d · ✅ satisfied: %d · ❌ violated: %d · 🛑 execution errors: %d · ⚠️ inconclusive: %d · ⏸ not run: %d\n\n", len(r.Cases), counts[Satisfied], counts[Violated], counts[ExecutionError], counts[Inconclusive], counts[NotRun])
	fmt.Fprintf(&b, "Acceptance cases: %d passed / %d failed. Failing IDs: %s\n\n", passed, len(failed), strings.Join(failed, ", "))
	if r.RunError != "" {
		fmt.Fprintf(&b, "Run failure: %s\n\n", escape(r.RunError))
	}
	b.WriteString("Baseline acceptance does not certify fail-closed egress. IPv6, SCTP and other IP protocols are outside this IPv4 TCP/UDP profile.\n\n| Case / scenario | Security requirement | Actual security result | Functionality | Baseline expected | Acceptance | Duration | Evidence / reason |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, c := range r.Cases {
		mark := "❌ FAIL"
		if r.CaseAccepted(c) {
			mark = "✅ PASS"
		}
		fmt.Fprintf(&b, "| %s | %s | %s %s | %s | %s | %s | %.3fs | `%s` %s |\n", escape(c.Name), escape(c.Requirement), icon[c.Actual], c.Actual, escape(c.Functionality), escape(c.Expected), mark, c.DurationSeconds, escape(c.Evidence), escape(c.Reason))
	}

	if !r.Finished.IsZero() {
		fmt.Fprintf(&b, "\nSuite wall time: %.3fs. Parallel operation durations overlap and must not be added to wall time.\n", r.Finished.Sub(r.Started).Seconds())
	}
	slow := slices.Clone(r.Cases)
	slices.SortFunc(slow, func(a, b CaseResult) int {
		if a.DurationSeconds > b.DurationSeconds {
			return -1
		}
		if a.DurationSeconds < b.DurationSeconds {
			return 1
		}
		return strings.Compare(a.ID, b.ID)
	})
	fmt.Fprint(&b, "\nSlowest executed cases:\n\n| Case | Duration |\n|---|---:|\n")
	for _, c := range slow[:min(10, len(slow))] {
		if c.Actual != NotRun {
			fmt.Fprintf(&b, "| %s | %.3fs |\n", escape(c.ID), c.DurationSeconds)
		}
	}
	fmt.Fprint(&b, "\n<details><summary>DNS case phase wall times</summary>\n\n| Case | Phase | Duration | Error |\n|---|---|---:|---|\n")
	for _, c := range r.Cases {
		for _, p := range c.Phases {
			fmt.Fprintf(&b, "| %s | %s | %.3fs | %s |\n", escape(c.ID), escape(p.Name), p.Seconds, escape(p.Error))
		}
	}
	fmt.Fprint(&b, "\n</details>\n")
	if len(r.Operations) > 0 {
		fmt.Fprint(&b, "\n<details><summary>Phase and operation timings</summary>\n\n| Operation | Duration | Error |\n|---|---:|---|\n")
		for _, op := range r.Operations {
			fmt.Fprintf(&b, "| `%s` | %.3fs | %s |\n", escape(op.Script), op.Seconds, escape(op.Error))
		}
		fmt.Fprint(&b, "\n</details>\n")
	}
	return b.String()
}

func (r *Report) junit() []byte {
	type failure struct {
		Message string `xml:"message,attr"`
		Text    string `xml:",chardata"`
	}
	type item struct {
		Name    string   `xml:"name,attr"`
		Class   string   `xml:"classname,attr"`
		Failure *failure `xml:"failure,omitempty"`
		Output  string   `xml:"system-out"`
		Time    float64  `xml:"time,attr"`
	}
	s := struct {
		XMLName  xml.Name `xml:"testsuite"`
		Name     string   `xml:"name,attr"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Cases    []item   `xml:"testcase"`
	}{Name: "networking-" + r.Mode}
	for _, c := range r.Cases {
		x := item{Name: c.Name, Class: c.ID, Time: c.DurationSeconds, Output: fmt.Sprintf("security=%s functionality=%s baseline=%s evidence=%s reason=%s", c.Actual, c.Functionality, c.Expected, c.Evidence, c.Reason)}
		if !r.CaseAccepted(c) {
			x.Failure = &failure{Message: c.Actual, Text: x.Output}
			if c.FunctionalityRequired && c.Functionality != "satisfied" {
				x.Failure.Message = "functionality not satisfied"
			}
			s.Failures++
		}
		s.Cases = append(s.Cases, x)
	}
	if r.RunError != "" {
		s.Cases = append(s.Cases, item{Name: "suite lifecycle", Class: "environment", Failure: &failure{Message: r.RunError}})
		s.Failures++
	}
	if s.Failures == 0 && !r.Accepted() {
		s.Cases = append(s.Cases, item{Name: "suite acceptance", Class: "environment", Failure: &failure{Message: "run is not finalized or reviewed baseline contract is not met"}})
		s.Failures++
	}
	s.Tests = len(s.Cases)
	data, _ := xml.MarshalIndent(s, "", "  ")
	return append([]byte(xml.Header), append(data, '\n')...)
}

// profileTags is shared by inventory and execution, including every OR branch.
func profileTags(profile, tags string) string {
	exclude := "~@calico"
	if profile == "calico-istio" {
		exclude = "~@istio-only"
	}
	if tags == "" {
		return exclude
	}
	clauses := strings.Split(tags, ",")
	for i := range clauses {
		clauses[i] = exclude + " && " + clauses[i]
	}
	return strings.Join(clauses, ",")
}

// Update serializes incremental evidence and its persisted report together.
func (r *Report) Update(change func(*Report)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	change(r)
	return r.save()
}
func (r *Report) Results() []CaseResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.Cases)
}
func (r *Report) AddOperation(op OperationTiming) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Operations = append(r.Operations, op)
}
