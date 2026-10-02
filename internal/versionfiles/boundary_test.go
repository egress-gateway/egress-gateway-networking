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
