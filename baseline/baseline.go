// Package baseline exposes the versioned, tested networking combination as data.
// It neither discovers nor certifies the caller's environment.
package baseline

import (
	_ "embed"
	"encoding/json"
)

//go:embed versions.json
var source []byte

type Versions struct {
	GoModules     map[string]string `json:"goModules"`
	Runtime       map[string]string `json:"runtime"`
	Calico        map[string]string `json:"calico"`
	Checksums     map[string]string `json:"checksums"`
	Images        map[string]string `json:"images"`
	GoMinimum     string            `json:"goMinimum"`
	GoCI          string            `json:"goCI"`
	Configuration Configuration     `json:"configuration"`
}

type Configuration struct {
	IPFamily      string `json:"ipFamily"`
	Dataplane     string `json:"dataplane"`
	Encapsulation string `json:"encapsulation"`
	Chained       bool   `json:"chained"`
	KubeProxy     bool   `json:"kubeProxy"`
}

// Current returns independent maps; mutating them cannot change subsequent calls.
func Current() Versions {
	var v Versions
	if err := json.Unmarshal(source, &v); err != nil {
		panic(err)
	}
	return v
}
