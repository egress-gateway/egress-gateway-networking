package suite

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEvidence(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
