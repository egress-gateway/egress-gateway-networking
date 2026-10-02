package suite

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func unavailableSocketMatrix() []socketObservation {
	var matrix []socketObservation
	for _, family := range []int{2, 10} {
		for typ := 1; typ <= 6; typ++ {
			for protocol := range 256 {
				matrix = append(matrix, socketObservation{Family: family, Type: typ, Protocol: protocol, Errno: 93})
			}
		}
	}
	return matrix
}

func TestSocketMatrixRejectsMissingAndUnexpectedPaths(t *testing.T) {
	matrix := unavailableSocketMatrix()
	for _, scenario := range []struct {
		name   string
		mutate func([]socketObservation) []socketObservation
		valid  bool
	}{
		{"unavailable", func(m []socketObservation) []socketObservation { return m }, true},
		{"missing", func(m []socketObservation) []socketObservation { return m[1:] }, false},
		{"duplicate", func(m []socketObservation) []socketObservation { m[0] = m[1]; return m }, false},
		{"resource-exhaustion", func(m []socketObservation) []socketObservation { m[0].Errno = 24; return m }, false},
		{"raw-available", func(m []socketObservation) []socketObservation { m[512].Errno = 0; return m }, false},
		{"unknown-protocol", func(m []socketObservation) []socketObservation {
			m[99].Errno, m[99].ActualProtocol = 0, 99
			return m
		}, false},
		{"tcp-default", func(m []socketObservation) []socketObservation {
			m[0].Errno, m[0].ActualProtocol = 0, 6
			return m
		}, true},
		{"protocol-substitution", func(m []socketObservation) []socketObservation {
			m[99].Errno, m[99].ActualProtocol = 0, 6
			return m
		}, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			err := validateSocketMatrix(scenario.mutate(slices.Clone(matrix)))
			if (err == nil) != scenario.valid {
				t.Fatalf("valid=%t, error=%v", scenario.valid, err)
			}
		})
	}
}

func TestUnavailableProtocolRequiresApplicationFailureAndOriginalPrivileges(t *testing.T) {
	for _, scenario := range []string{"unavailable", "missing-attempt", "wrong-errno", "privileged", "available-alternative", "unrelated-attempt"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			start := time.Now().UTC()
			state := namespaceState{ID: "request", Event: "network-state", UID: 10000, GID: 10000, Started: start, Finished: start, Sockets: unavailableSocketMatrix(), Identity: map[string]string{"Uid": "10000 10000 10000 10000", "Gid": "10000 10000 10000 10000", "CapInh": "0", "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0", "NoNewPrivs": "1", "Seccomp": "2"}}
			probe := probeRecord{ID: "request", Protocol: "sctp", UID: 10000, Attempted: true, Started: start.Add(time.Second), SocketError: 93}
			switch scenario {
			case "missing-attempt":
				probe.Attempted = false
			case "wrong-errno":
				probe.SocketError = 111
			case "privileged":
				state.Identity["CapEff"] = "2000"
			case "available-alternative":
				state.Sockets[4*256+132].Errno = 0
				state.Sockets[4*256+132].ActualProtocol = 132
			case "unrelated-attempt":
				probe.ID = "other"
			}
			for name, value := range map[string]any{"network-state.json": state, "probe.jsonl": probe} {
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			actual, reason, err := evaluateProtocol(dir, "request", "protocol-closure", egressInputs{Protocol: "sctp", Target: "np-protocol", Phase: "healthy"})
			if err != nil || (actual == Satisfied) != (scenario == "unavailable") {
				t.Fatalf("result=%s reason=%s error=%v", actual, reason, err)
			}
		})
	}
}
