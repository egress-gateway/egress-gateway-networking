package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
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

func checkTopology(kind, cni []byte, v baseline.Configuration) error {
	var cluster struct {
		Networking struct {
			IPFamily      string `yaml:"ipFamily"`
			KubeProxyMode string `yaml:"kubeProxyMode"`
		}
	}
	var plugin struct{ Chained *bool }
	if err := yaml.Unmarshal(kind, &cluster); err != nil {
		return err
	}
	if err := yaml.Unmarshal(cni, &plugin); err != nil {
		return err
	}
	if !strings.EqualFold(cluster.Networking.IPFamily, v.IPFamily) || cluster.Networking.KubeProxyMode == "" || (cluster.Networking.KubeProxyMode != "none") != v.KubeProxy {
		return errors.New("kind IP family or kube-proxy configuration differs from baseline")
	}
	if v.KubeProxy && cluster.Networking.KubeProxyMode != "iptables" {
		return errors.New("enabled kube-proxy must use the supported iptables mode")
	}
	if plugin.Chained == nil || *plugin.Chained != v.Chained {
		return errors.New("Istio CNI chaining differs from baseline")
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
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	found := false
	for {
		var doc struct {
			Kind     string
			Metadata struct{ Labels map[string]string }
			Spec     struct {
				CalicoNetwork struct {
					LinuxDataplane      string `yaml:"linuxDataplane"`
					KubeProxyManagement string `yaml:"kubeProxyManagement"`
					IPPools             []struct {
						CIDR          string `yaml:"cidr"`
						Encapsulation string
					} `yaml:"ipPools"`
				} `yaml:"calicoNetwork"`
			}
		}
		if err := decoder.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if doc.Kind != "Installation" {
			continue
		}
		if found {
			return errors.New("duplicate Calico Installation")
		}
		found = true
		if doc.Metadata.Labels["networking.egress/managed"] != "calico-"+v.Calico["CALICO_VERSION"] {
			return errors.New("Calico installation label differs from baseline")
		}
		n := doc.Spec.CalicoNetwork
		if n.LinuxDataplane != v.Configuration.Dataplane || len(n.IPPools) == 0 {
			return errors.New("Calico dataplane or pools differ from baseline")
		}
		if !v.Configuration.KubeProxy || n.KubeProxyManagement != "Disabled" {
			return errors.New("Calico must retain the baseline's separately managed kube-proxy")
		}
		for _, pool := range n.IPPools {
			prefix, err := netip.ParsePrefix(pool.CIDR)
			if err != nil || v.Configuration.IPFamily != "IPv4" || !prefix.Addr().Is4() || pool.Encapsulation != v.Configuration.Encapsulation {
				return errors.New("Calico pool family or encapsulation differs from baseline")
			}
		}
	}
	if !found {
		return errors.New("missing Calico Installation")
	}
	return nil
}
