package environment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCalicoBootstrapOrder(t *testing.T) {
	e, calls := testEnvironment(t)
	if err := e.Run(t.Context(), "e2e"); err != nil {
		t.Fatal(err)
	}
	install := slices.Index(*calls, "install/scripts/install.sh")
	fixtures := slices.Index(*calls, "test/e2e/scripts/np-up.sh")
	suite := slices.Index(*calls, "suite")
	if install < 0 || fixtures <= install || suite <= fixtures {
		t.Fatalf("unsafe order: %v", *calls)
	}
}
func TestLegacyRetainedProfileRefusesTestsButAllowsOwnedCleanup(t *testing.T) {
	e, calls := testEnvironment(t)
	if err := e.Run(t.Context(), "up"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.State, "environment.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err = json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	record["profile"] = "calico-istio"
	data, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	if err = e.Run(t.Context(), "test"); err == nil {
		t.Fatal("legacy profile accepted")
	}
	if slices.Contains(*calls, "suite") {
		t.Fatal("executed obsolete suite")
	}
	if err = e.Run(t.Context(), "down"); err != nil {
		t.Fatal(err)
	}
}
