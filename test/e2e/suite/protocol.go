package suite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type socketObservation struct {
	Family         int `json:"family"`
	Type           int `json:"type"`
	Protocol       int `json:"protocol"`
	ActualProtocol int `json:"actual_protocol"`
	Errno          int `json:"errno"`
}

type namespaceState struct {
	ID          string              `json:"id"`
	Event       string              `json:"event"`
	UID         int                 `json:"uid"`
	GID         int                 `json:"gid"`
	Started     time.Time           `json:"started"`
	Finished    time.Time           `json:"finished"`
	Identity    map[string]string   `json:"identity"`
	Addresses   map[string][]string `json:"addresses"`
	DisableIPv6 map[string]string   `json:"disable_ipv6"`
	Files       map[string]string   `json:"files"`
	Sockets     []socketObservation `json:"sockets"`
}

func readNamespaceState(dir, id string) (namespaceState, error) {
	var state namespaceState
	data, err := os.ReadFile(filepath.Join(dir, "network-state.json"))
	if err != nil {
		return state, err
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if state.ID != id || state.Event != "network-state" || state.Started.IsZero() || state.Finished.Before(state.Started) || state.UID != 10000 || state.GID != 10000 {
		return state, errors.New("namespace evidence identity or interval invalid")
	}
	for _, key := range []string{"Uid", "Gid"} {
		if values := strings.Fields(state.Identity[key]); len(values) != 4 || !slices.Equal(values, []string{"10000", "10000", "10000", "10000"}) {
			return state, fmt.Errorf("unexpected application %s", key)
		}
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, err := strconv.ParseUint(state.Identity[key], 16, 64)
		if err != nil || value != 0 {
			return state, fmt.Errorf("application capability %s not proven absent", key)
		}
	}
	if state.Identity["NoNewPrivs"] != "1" || state.Identity["Seccomp"] != "2" {
		return state, errors.New("application privilege envelope changed")
	}
	return state, nil
}

func validateSocketMatrix(sockets []socketObservation) error {
	seen := make(map[[3]int]bool, 3072)
	for _, socket := range sockets {
		key := [3]int{socket.Family, socket.Type, socket.Protocol}
		if seen[key] || !slices.Contains([]int{2, 10}, socket.Family) || !slices.Contains([]int{1, 2, 3, 4, 5, 6}, socket.Type) || socket.Protocol < 0 || socket.Protocol > 255 {
			return errors.New("socket matrix contains duplicate or invalid coordinates")
		}
		seen[key] = true
		if socket.Errno != 0 {
			// Linux EPERM/EACCES and unsupported family/type/protocol are closure;
			// resource exhaustion and transient system errors are missing evidence.
			if !slices.Contains([]int{1, 13, 93, 94, 97}, socket.Errno) {
				return fmt.Errorf("unclassified socket failure at %v: errno %d", key, socket.Errno)
			}
			continue
		}
		valid := false
		switch socket.Type {
		case 1:
			valid = socket.ActualProtocol == 6 || socket.ActualProtocol == 132
		case 2:
			valid = socket.ActualProtocol == 17 || socket.ActualProtocol == 136 || socket.Family == 2 && socket.ActualProtocol == 1 || socket.Family == 10 && socket.ActualProtocol == 58
		case 5:
			valid = socket.ActualProtocol == 132
		}
		if !valid || socket.Protocol != 0 && socket.ActualProtocol != socket.Protocol {
			return fmt.Errorf("available untested socket at %v: actual protocol %d", key, socket.ActualProtocol)
		}
	}
	if len(seen) != 3072 {
		return fmt.Errorf("socket matrix incomplete: %d of 3072 observations", len(seen))
	}
	return nil
}

func evaluateProtocol(dir, id, contract string, expected egressInputs) (string, string, error) {
	state, err := readNamespaceState(dir, id)
	if err != nil {
		return ExecutionError, err.Error(), nil
	}
	if err := validateSocketMatrix(state.Sockets); err != nil {
		return Inconclusive, err.Error(), nil
	}
	if expected.Target == "np-socket-matrix" && contract == "socket-matrix" && expected.Protocol == "inventory" && expected.Phase == "healthy" {
		return Satisfied, "complete restricted-process socket matrix: remaining IP protocols unavailable; TCP/UDP, SCTP, ICMP, UDP-Lite and IPv6 communication require their separate cases", nil
	}
	if expected.Target != "np-protocol" || contract != "protocol-closure" || expected.Phase != "healthy" {
		return ExecutionError, "invalid protocol case inputs", nil
	}
	number, typ := 0, 2
	switch expected.Protocol {
	case "sctp":
		number, typ = 132, 1
	case "icmp":
		number = 1
	case "udplite":
		number = 136
	default:
		return ExecutionError, "unknown protocol case", nil
	}
	for _, socket := range state.Sockets {
		if socket.Family != 2 || socket.Type != typ || socket.Protocol != number {
			continue
		}
		if socket.Errno == 0 {
			target := "np-protocol-receiver"
			if expected.Protocol == "udplite" {
				target = "np-udplite"
			}
			return evaluateNetwork(filepath.Join(dir, "path"), id, "deny", egressInputs{Protocol: expected.Protocol, Target: target, Phase: "healthy"})
		}
		for _, alternative := range state.Sockets {
			if alternative.Family == 2 && alternative.ActualProtocol == number && alternative.Errno == 0 {
				return Inconclusive, "protocol has an available socket mode without a working application probe", nil
			}
		}
		probes, err := records(filepath.Join(dir, "probe.jsonl"))
		if err != nil {
			return "", "", err
		}
		for _, probe := range probes {
			if probe.ID == id && probe.Protocol == expected.Protocol && probe.UID == 10000 && probe.Attempted && !probe.Success && probe.SocketError == socket.Errno && !probe.Started.Before(state.Finished) {
				return Satisfied, fmt.Sprintf("protocol unavailable to restricted application: actual socket attempt errno %d agrees with complete socket matrix", socket.Errno), nil
			}
		}
		return Inconclusive, "unavailable protocol lacks matching application socket failure", nil
	}
	return ExecutionError, "missing protocol socket observation", nil
}
