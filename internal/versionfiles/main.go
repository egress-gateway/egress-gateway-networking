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
	fmt.Fprintf(&b, "# Generated from baseline/versions.json; do not edit.\napiVersion: operator.tigera.io/v1\nkind: ImageSet\nmetadata:\n  name: calico-%s\nspec:\n  images:\n", v.Calico["CALICO_VERSION"])
	for _, k := range slices.Sorted(maps.Keys(v.Images)) {
		fmt.Fprintf(&b, "    - image: %s\n      digest: %s\n", k, v.Images[k])
	}
	files["install/calico/images.yaml"] = b.String()
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
		if !strings.Contains(string(data), "go-version: '"+v.GoCI+"'") {
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
	if err != nil || !strings.Contains(string(data), "calico-"+v.Calico["CALICO_VERSION"]) {
		fail("Calico installation label differs from baseline")
	}
}

func fail(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
