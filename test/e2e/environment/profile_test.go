package environment

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestCalicoRunsNetworkPolicyBDDBeforeInstallingIstio(t *testing.T) {
	e, calls := testEnvironment(t)
	e.Profile = "calico-istio"
	e.PolicyTest = func(context.Context) error { *calls = append(*calls, "np-bdd"); return nil }
	if err := e.Run(t.Context(), "e2e"); err != nil {
		t.Fatal(err)
	}
	primary := slices.Index(*calls, "install/scripts/calico-install.sh")
	np := slices.Index(*calls, "np-bdd")
	mesh := slices.Index(*calls, "install/scripts/install.sh")
	if primary < 0 || np <= primary || mesh <= np {
		t.Fatalf("wrong bootstrap order: %v", *calls)
	}
}

func TestFailedPolicyBDDStopsBeforeIstioAndDiagnoses(t *testing.T) {
	e, calls := testEnvironment(t)
	e.Profile = "calico-istio"
	e.PolicyTest = func(context.Context) error { return errors.New("NP-08 received forbidden packet") }
	if err := e.Run(t.Context(), "e2e"); err == nil {
		t.Fatal("NP failure passed")
	}
	if slices.Contains(*calls, "install/scripts/install.sh") || slices.Contains(*calls, "suite") {
		t.Fatalf("continued beyond failed NP: %v", *calls)
	}
	if !slices.Contains(*calls, "environments/kind/diagnostics.sh") {
		t.Fatal("failure has no diagnostics")
	}
}

func TestRetainedProfileMismatchRefusesAccessButAllowsOwnedCleanup(t *testing.T) {
	e, calls := testEnvironment(t)
	if err := e.Run(t.Context(), "up"); err != nil {
		t.Fatal(err)
	}
	*calls = nil
	e.Profile = "calico-istio"
	if err := e.Run(t.Context(), "test"); err == nil {
		t.Fatal("profile mismatch accepted")
	}
	if slices.Contains(*calls, "suite") {
		t.Fatal("mismatched environment executed tests")
	}
	if err := e.Run(t.Context(), "down"); err != nil {
		t.Fatal(err)
	}
}
