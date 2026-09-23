package main

import (
	"path/filepath"
	"testing"
)

func TestOutputDirectoriesStaySeparate(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name      string
		state     string
		artifacts string
		wantError bool
	}{
		{name: "default siblings", state: ".e2e/state", artifacts: ".e2e/artifacts"},
		{name: "shared name prefix", state: ".e2e/state", artifacts: ".e2e/state-reports"},
		{name: "separate nested paths", state: "private/state", artifacts: "reports/networking"},
		{name: "same directory", state: ".e2e/state", artifacts: ".e2e/state", wantError: true},
		{name: "artifacts inside state", state: ".e2e/state", artifacts: ".e2e/state/reports", wantError: true},
		{name: "state inside artifacts", state: ".e2e/artifacts/state", artifacts: ".e2e/artifacts", wantError: true},
		{name: "artifacts at e2e parent", state: ".e2e/state", artifacts: ".e2e", wantError: true},
		{name: "artifacts at repository root", state: ".e2e/state", artifacts: ".", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOutputPaths(filepath.Join(root, tc.state), filepath.Join(root, tc.artifacts))
			if (err != nil) != tc.wantError {
				t.Fatalf("state=%q artifacts=%q: error=%v, wantError=%t", tc.state, tc.artifacts, err, tc.wantError)
			}
		})
	}
}
