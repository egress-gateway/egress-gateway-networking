// Command versionfiles maintains checked-in Shell/YAML consumers of baseline data.
package main

import (
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/egress-gateway/egress-gateway-networking/baseline"
)

func main() {
	check := flag.Bool("check", false, "verify generated files without writing")
	flag.Parse()
	v := baseline.Current()
	files := map[string]string{}
	for path, values := range map[string]map[string]string{"install/versions.env": v.Runtime, "install/calico/versions.env": v.Calico, "scripts/ci-tools.env": v.Checksums} {
		var b strings.Builder
		b.WriteString("# Generated from baseline/versions.json; do not edit.\n")
		for _, k := range slices.Sorted(maps.Keys(values)) {
			fmt.Fprintf(&b, "%s=%s\n", k, values[k])
		}
		files[path] = b.String()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# Generated from baseline/versions.json; do not edit.\napiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nnamespace: calico-system\nresources: [upstream.yaml, namespace.yaml]\nlabels:\n  - pairs:\n      networking.egress/managed: calico-static-%s\n    includeSelectors: false\nimages:\n", v.Calico["CALICO_VERSION"])
	for _, k := range slices.Sorted(maps.Keys(v.Images)) {
		fmt.Fprintf(&b, "  - name: quay.io/%s\n    newTag: %s\n    digest: %s\n", k, v.Calico["CALICO_VERSION"], v.Images[k])
	}
	b.WriteString("patches:\n  - path: node-patch.json\n  - path: config-patch.json\n  - target: {kind: Deployment, name: calico-kube-controllers}\n    patch: |-\n      - op: remove\n        path: /spec/template/metadata/namespace\n")
	files["install/calico/kustomization.yaml"] = b.String()
	for path, want := range files {
		if *check {
			got, err := os.ReadFile(path)
			if err != nil || string(got) != want {
				fail("%s differs from baseline; run go run ./internal/versionfiles", path)
			}
		} else if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			fail("%v", err)
		}
	}
	for _, path := range []string{".github/workflows/check.yaml", ".github/workflows/e2e.yaml"} {
		data, err := os.ReadFile(path)
		if err != nil {
			fail("%v", err)
		}
		if err := checkWorkflow(data, v.GoCI); err != nil {
			fail("%s: Go CI pin differs from baseline", path)
		}
	}
	data, err := os.ReadFile("go.mod")
	if err != nil || !strings.Contains(string(data), "\ngo "+v.GoMinimum+"\n") {
		fail("go.mod differs from baseline")
	}
	for module, version := range v.GoModules {
		found := false
		for line := range strings.SplitSeq(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == module {
				found = fields[1] == version
			}
		}
		if !found {
			fail("go.mod: %s differs from baseline", module)
		}
	}
	data, err = os.ReadFile("install/calico/installation.yaml")
	if err != nil {
		fail("%v", err)
	}
	if err := checkInstallation(data, v); err != nil {
		fail("%v", err)
	}
	node, err := os.ReadFile("install/calico/node-patch.json")
	if err != nil {
		fail("%v", err)
	}
	config, err := os.ReadFile("install/calico/config-patch.json")
	if err != nil {
		fail("%v", err)
	}
	if err := checkCalicoConfiguration(node, config, v); err != nil {
		fail("%v", err)
	}
	kind, err := os.ReadFile("environments/kind/cluster.yaml")
	if err != nil {
		fail("%v", err)
	}
	if err := checkTopology(kind, v.Configuration); err != nil {
		fail("%v", err)
	}
}
func fail(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
