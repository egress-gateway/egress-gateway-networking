package suite

import (
	"strings"
	"testing"
)

func TestMTLSRequiresBothDirectionsAndCorrectIdentities(t *testing.T) {
	client := access{ID: "request", Code: "200", Method: "GET", Path: "/headers", UpstreamTLS: "TLSv1.3", UpstreamPeer: serverIdentity, Cluster: serviceCluster}
	server := access{ID: "request", Code: "200", Method: "GET", Path: "/headers", DownstreamTLS: "TLSv1.3", DownstreamPeer: clientIdentity}
	if err := checkMTLS(client, server); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(*access, *access)
	}{
		{"client plaintext", func(c, s *access) { c.UpstreamTLS = "-" }},
		{"server plaintext", func(c, s *access) { s.DownstreamTLS = "" }},
		{"wrong client identity", func(c, s *access) { s.DownstreamPeer = serverIdentity }},
		{"wrong server identity", func(c, s *access) { c.UpstreamPeer = clientIdentity }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, s := client, server
			tt.change(&c, &s)
			if checkMTLS(c, s) == nil {
				t.Fatal("accepted incomplete mTLS proof")
			}
		})
	}
}

func TestAccessEvidenceMustMatchTheRequest(t *testing.T) {
	logs := "non-json startup\n" + `{"test_id":"other","code":200,"method":"GET","path":"/headers"}` + "\n"
	if _, err := findAccess(strings.NewReader(logs), "wanted"); err == nil {
		t.Fatal("accepted another request")
	}
	logs += `{"test_id":"wanted","code":503,"method":"GET","path":"/headers"}` + "\n"
	if _, err := findAccess(strings.NewReader(logs), "wanted"); err == nil {
		t.Fatal("accepted failed proxy response")
	}
	for _, code := range []string{`200`, `"200"`} {
		line := `{"test_id":"wanted","code":` + code + `,"method":"GET","path":"/headers"}`
		if _, err := findAccess(strings.NewReader(line), "wanted"); err != nil {
			t.Fatalf("valid Envoy response code %s: %v", code, err)
		}
	}
}

func TestPlaintextRequiresServerRejectionNotJustClientFailure(t *testing.T) {
	for _, tt := range []struct {
		name, code   string
		rc           int
		rejected, ok bool
	}{
		{"reset with rejection", "000", 56, true, true},
		{"timeout only", "000", 28, false, false},
		{"reset without server evidence", "000", 56, false, false},
		{"application response", "200", 0, true, false},
		{"kubectl failure", "000", 1, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkRejection(tt.code, tt.rc, tt.rejected)
			if (err == nil) != tt.ok {
				t.Fatalf("got %v, want accepted=%v", err, tt.ok)
			}
		})
	}
}

func TestRejectionLogMustIdentifyThisPlaintextClient(t *testing.T) {
	for _, tt := range []struct {
		name, line string
		ok         bool
	}{
		{"matched listener rejection", `{"source_ip":"10.244.0.9","code":0,"details":"filter_chain_not_found","downstream_tls":null}`, true},
		{"another client", `{"source_ip":"10.244.0.10","code":0,"details":"filter_chain_not_found"}`, false},
		{"HTTP denial", `{"source_ip":"10.244.0.9","code":403,"details":"rbac_access_denied"}`, false},
		{"unrelated error", `{"source_ip":"10.244.0.9","code":0,"details":"upstream_reset"}`, false},
		{"unidentified client", `{"source_ip":null,"code":0,"details":"filter_chain_not_found"}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findRejection(strings.NewReader(tt.line), "10.244.0.9")
			if err != nil || got != tt.ok {
				t.Fatalf("matched=%v err=%v", got, err)
			}
		})
	}
}
