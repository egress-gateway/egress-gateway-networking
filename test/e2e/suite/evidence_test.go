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
		name, code        string
		rc, before, after int
		ok                bool
	}{
		{"reset with rejection", "000", 56, 3, 4, true},
		{"timeout only", "000", 28, 3, 3, false},
		{"reset without server evidence", "000", 56, 3, 3, false},
		{"application response", "200", 0, 3, 4, false},
		{"counter reset", "000", 56, 3, 1, false},
		{"kubectl failure", "000", 1, 3, 4, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkRejection(tt.code, tt.rc, tt.before, tt.after)
			if (err == nil) != tt.ok {
				t.Fatalf("got %v, want accepted=%v", err, tt.ok)
			}
		})
	}
}
