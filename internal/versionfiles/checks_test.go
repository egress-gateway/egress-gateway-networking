package main

import (
	"os"
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway-networking/baseline"
)

func TestWorkflowPinsIgnoreCommentsAndDisabledSteps(t *testing.T) {
	v := baseline.Current().GoCI
	base := "jobs:\n  check:\n    steps:\n      - uses: actions/setup-go@v5\n        with:\n          go-version: '" + v + "'\n"
	for name, data := range map[string]string{
		"valid":              base,
		"comment":            "# go-version: '" + v + "'\n" + strings.Replace(base, v, "1.1.0", 1),
		"disabled-step":      "jobs:\n  check:\n    steps:\n      - uses: actions/setup-go@v5\n        if: false\n        with: {go-version: '" + v + "'}\n      - uses: actions/setup-go@v5\n        with: {go-version: '1.1.0'}\n",
		"disabled-job":       strings.Replace(base, "    steps:", "    if: false\n    steps:", 1),
		"ignore-disabled":    base + "      - uses: actions/setup-go@v5\n        if: ${{ false }}\n        with: {go-version: '1.1.0'}\n",
		"conditional-active": base + "      - uses: actions/setup-go@v5\n        if: ${{ runner.os == 'Linux' }}\n        with: {go-version: '1.1.0'}\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := checkWorkflow([]byte(data), v)
			want := name == "valid" || name == "ignore-disabled"
			if (err == nil) != want {
				t.Fatalf("accepted=%v: %v", err == nil, err)
			}
		})
	}
}

func TestInstallationSettingsMatchBaseline(t *testing.T) {
	data, err := os.ReadFile("../../install/calico/installation.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{"", ""}, {"defaultEndpointToHostAction: Accept", "defaultEndpointToHostAction: Drop"}, {"ipv6Support: false", "ipv6Support: true"}, {"bpfEnabled: false", "bpfEnabled: true"}, {"chainInsertMode: Insert", "chainInsertMode: Append"}, {"calico-static-v3.32.2", "calico-static-v0.0.0"}} {
		t.Run(change[0], func(t *testing.T) {
			input := string(data)
			if change[0] != "" {
				input = strings.Replace(input, change[0], change[1], 1)
			}
			err := checkInstallation([]byte(input), baseline.Current())
			if (err == nil) != (change[0] == "") {
				t.Fatalf("accepted=%v: %v", err == nil, err)
			}
		})
	}
}

func TestTopologyMatchesBaseline(t *testing.T) {
	kind, err := os.ReadFile("../../environments/kind/cluster.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, kind string
		valid      bool
	}{
		{"valid", string(kind), true},
		{"proxy-disabled", strings.Replace(string(kind), "kubeProxyMode: iptables", "kubeProxyMode: none", 1), false},
		{"proxy-ipvs", strings.Replace(string(kind), "kubeProxyMode: iptables", "kubeProxyMode: ipvs", 1), false},
		{"proxy-nftables", strings.Replace(string(kind), "kubeProxyMode: iptables", "kubeProxyMode: nftables", 1), false},
		{"proxy-empty", strings.Replace(string(kind), "kubeProxyMode: iptables", "kubeProxyMode: ", 1), false},
		{"wrong-family", strings.Replace(string(kind), "ipFamily: ipv4", "ipFamily: ipv6", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkTopology([]byte(tc.kind), baseline.Current().Configuration); (err == nil) != tc.valid {
				t.Fatalf("%v", err)
			}
		})
	}
}
