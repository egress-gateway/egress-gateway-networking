package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/egress-gateway/egress-gateway-networking/baseline"
	"go.yaml.in/yaml/v2"
)

// Dynamic conditions remain potentially active; only literal false is skipped.
func disabled(condition any) bool {
	if condition == false {
		return true
	}
	s, ok := condition.(string)
	if !ok {
		return false
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		s = strings.TrimSpace(s[3 : len(s)-2])
	}
	return s == "false"
}

func checkTopology(kind []byte, v baseline.Configuration) error {
	var cluster struct {
		Networking struct {
			IPFamily      string `yaml:"ipFamily"`
			KubeProxyMode string `yaml:"kubeProxyMode"`
		}
	}
	if err := yaml.Unmarshal(kind, &cluster); err != nil {
		return err
	}
	if !strings.EqualFold(cluster.Networking.IPFamily, v.IPFamily) || cluster.Networking.KubeProxyMode == "" || (cluster.Networking.KubeProxyMode != "none") != v.KubeProxy {
		return errors.New("kind IP family or kube-proxy configuration differs from baseline")
	}
	if v.KubeProxy && cluster.Networking.KubeProxyMode != "iptables" {
		return errors.New("enabled kube-proxy must use the supported iptables mode")
	}
	return nil
}

func checkWorkflow(data []byte, version string) error {
	var workflow struct {
		Jobs map[string]struct {
			If    any
			Steps []struct {
				If   any
				Uses string
				With map[string]string
			}
		}
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return err
	}
	found := false
	for name, job := range workflow.Jobs {
		if disabled(job.If) {
			continue
		}
		for _, step := range job.Steps {
			if disabled(step.If) || !strings.HasPrefix(step.Uses, "actions/setup-go@") {
				continue
			}
			found = true
			if step.With["go-version"] != version || step.With["go-version-file"] != "" {
				return fmt.Errorf("job %s: active setup-go pin differs from baseline", name)
			}
		}
	}
	if !found {
		return errors.New("no active setup-go pin")
	}
	return nil
}

func checkInstallation(data []byte, v baseline.Versions) error {
	var doc struct {
		Kind     string
		Metadata struct {
			Name   string
			Labels map[string]string
		}
		Spec struct {
			HostAction string `yaml:"defaultEndpointToHostAction"`
			ChainMode  string `yaml:"chainInsertMode"`
			IPv6       *bool  `yaml:"ipv6Support"`
			BPF        *bool  `yaml:"bpfEnabled"`
		}
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc.Kind != "FelixConfiguration" || doc.Metadata.Name != "default" || doc.Metadata.Labels["networking.egress/managed"] != "calico-static-"+v.Calico["CALICO_VERSION"] || doc.Spec.HostAction != "Accept" || doc.Spec.ChainMode != "Insert" || doc.Spec.IPv6 == nil || *doc.Spec.IPv6 || doc.Spec.BPF == nil || *doc.Spec.BPF {
		return errors.New("Calico Felix configuration differs from the supported boundary")
	}
	return nil
}

func checkCalicoConfiguration(node, config []byte, v baseline.Versions) error {
	var ds struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Name string
						Env  []struct{ Name, Value string }
					}
				}
			}
		}
	}
	if err := json.Unmarshal(node, &ds); err != nil {
		return err
	}
	env := map[string]string{}
	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name == "calico-node" {
			for _, e := range c.Env {
				env[e.Name] = e.Value
			}
		}
	}
	for key, value := range map[string]string{"CALICO_IPV4POOL_CIDR": "10.244.0.0/16", "CALICO_IPV4POOL_IPIP": "Never", "CALICO_IPV4POOL_VXLAN": "Always", "FELIX_BPFENABLED": "false", "FELIX_DEFAULTENDPOINTTOHOSTACTION": "ACCEPT", "FELIX_CHAININSERTMODE": "Insert", "FELIX_IPV6SUPPORT": "false", "FELIX_ENDPOINTSTATUSPATHPREFIX": "/var/run/calico"} {
		if env[key] != value {
			return fmt.Errorf("Calico %s differs from supported configuration", key)
		}
	}
	if v.Configuration.IPFamily != "IPv4" || v.Configuration.Dataplane != "Iptables" || v.Configuration.Encapsulation != "VXLAN" || !v.Configuration.KubeProxy {
		return errors.New("unsupported baseline dataplane")
	}
	var cm struct{ Data map[string]string }
	if err := json.Unmarshal(config, &cm); err != nil {
		return err
	}
	if cm.Data["calico_backend"] != "vxlan" {
		return errors.New("Calico backend must be VXLAN")
	}
	var cni struct {
		Plugins []struct {
			Type string
			Wait int `json:"policy_setup_timeout_seconds"`
			IPAM struct {
				IPv4 string `json:"assign_ipv4"`
				IPv6 string `json:"assign_ipv6"`
			}
			Sysctl map[string]string
		}
	}
	if err := json.Unmarshal([]byte(strings.ReplaceAll(cm.Data["cni_network_config"], "__CNI_MTU__", "0")), &cni); err != nil {
		return err
	}
	if len(cni.Plugins) != 3 || cni.Plugins[0].Type != "calico" || cni.Plugins[0].Wait != 10 || cni.Plugins[0].IPAM.IPv4 != "true" || cni.Plugins[0].IPAM.IPv6 != "false" || cni.Plugins[1].Type != "tuning" || len(cni.Plugins[1].Sysctl) != 2 || cni.Plugins[1].Sysctl["net.ipv6.conf.all.disable_ipv6"] != "1" || cni.Plugins[1].Sysctl["net.ipv6.conf.default.disable_ipv6"] != "1" || cni.Plugins[2].Type != "portmap" {
		return errors.New("CNI chain must wait for policy and disable all Pod IPv6 before startup")
	}
	return nil
}
