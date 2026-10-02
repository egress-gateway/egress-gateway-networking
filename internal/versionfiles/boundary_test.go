package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/baseline"
)

func TestEffectiveBoundaryRejectsMissingDisablementAndWrongNodeAction(t *testing.T) {
	node, err := os.ReadFile("../../install/calico/node-patch.json")
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile("../../install/calico/config-patch.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCalicoConfiguration(node, config, baseline.Current()); err != nil {
		t.Fatal(err)
	}
	var cm struct{ Data map[string]string }
	if err := json.Unmarshal(config, &cm); err != nil {
		t.Fatal(err)
	}
	cni := strings.ReplaceAll(cm.Data["cni_network_config"], "__CNI_MTU__", "0")
	for _, change := range [][2]string{{"", ""}, {`"net.ipv6.conf.all.disable_ipv6": "1"`, `"net.ipv6.conf.all.disable_ipv6": "0"`}, {`"net.ipv6.conf.default.disable_ipv6"`, `"unrecognized"`}, {`"policy_setup_timeout_seconds": 10`, `"policy_setup_timeout_seconds": 0`}, {`"type": "tuning"`, `"type": "unknown"`}, {`"assign_ipv6": "false"`, `"assign_ipv6": "true"`}} {
		t.Run(change[0], func(t *testing.T) {
			data := cni
			if change[0] != "" {
				data = strings.Replace(data, change[0], change[1], 1)
			}
			cmd := exec.CommandContext(t.Context(), "jq", "-e", "-f", "../../install/scripts/check-cni.jq")
			cmd.Stdin = strings.NewReader(data)
			err := cmd.Run()
			if (err == nil) != (change[0] == "") {
				t.Fatalf("accepted=%t: %v", err == nil, err)
			}
		})
	}
	var ds map[string]any
	if err := json.Unmarshal(node, &ds); err != nil {
		t.Fatal(err)
	}
	ds["metadata"].(map[string]any)["labels"] = map[string]string{"networking.egress/managed": "calico-static-v3.32.2"}
	valid, err := json.Marshal(ds)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"ACCEPT", "DROP", "RETURN", ""} {
		t.Run("node-"+action, func(t *testing.T) {
			input := strings.Replace(string(valid), `"ACCEPT"`, `"`+action+`"`, 1)
			cmd := exec.CommandContext(t.Context(), "jq", "-e", "--arg", "owner", "calico-static-v3.32.2", "-f", "../../install/scripts/check-node.jq")
			cmd.Stdin = strings.NewReader(input)
			err := cmd.Run()
			if (err == nil) != (action == "ACCEPT") {
				t.Fatalf("accepted=%t: %v", err == nil, err)
			}
		})
	}
}

func TestCNICompositionChecksOnlySelectedFoundationScope(t *testing.T) {
	data, err := os.ReadFile("../../install/calico/config-patch.json")
	if err != nil {
		t.Fatal(err)
	}
	var cm struct{ Data map[string]string }
	if err := json.Unmarshal(data, &cm); err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(strings.ReplaceAll(cm.Data["cni_network_config"], "__CNI_MTU__", "0")), &config); err != nil {
		t.Fatal(err)
	}
	base := config["plugins"].([]any)
	suffix := map[string]any{"type": "consumer-owned"}
	for _, tc := range []struct {
		name, scope string
		plugins     []any
		accepted    bool
	}{
		{"standalone", "standalone", base, true},
		{"unknown scope", "unknown", base, false},
		{"foundation alone", "foundation", base, true},
		{"unselected composition", "standalone", append(append([]any{}, base...), suffix), false},
		{"consumer suffix", "foundation", append(append([]any{}, base...), suffix), true},
		{"missing tuning", "foundation", []any{base[0], base[2], suffix}, false},
		{"wrong order", "foundation", []any{base[0], base[2], base[1], suffix}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config["plugins"] = tc.plugins
			input, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), "jq", "-e", "--arg", "scope", tc.scope, "-f", "../../install/scripts/check-cni.jq")
			cmd.Stdin = strings.NewReader(string(input))
			if err := cmd.Run(); (err == nil) != tc.accepted {
				t.Fatalf("accepted=%t: %v", err == nil, err)
			}
		})
	}
}
