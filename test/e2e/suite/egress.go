package suite

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

type probeRecord struct {
	UID           int       `json:"uid"`
	Dropped       *uint32   `json:"dropped"`
	KernelPackets *uint32   `json:"kernel_packets"`
	Captured      *uint32   `json:"captured"`
	Started       time.Time `json:"started"`
	Finished      time.Time `json:"finished"`
	Time          time.Time `json:"time"`
	ID            string    `json:"id"`
	Event         string    `json:"event"`
	Protocol      string    `json:"protocol"`
	Attempted     bool      `json:"attempted"`
	Connected     bool      `json:"connected"`
	Success       bool      `json:"success"`
	Local         string    `json:"local"`
	Remote        string    `json:"remote"`
	Destination   string    `json:"destination"`
	Interface     string    `json:"interface"`
	Reason        string    `json:"reason"`
	Digest        string    `json:"digest"`
	Error         string    `json:"error"`
}

func records(path string) ([]probeRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var results []probeRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var p probeRecord
		if err := json.Unmarshal(line, &p); err != nil {
			return nil, fmt.Errorf("%s:%d: invalid evidence record: %w", path, lineNumber, err)
		}
		results = append(results, p)
	}
	return results, scanner.Err()
}

type egressInputs struct {
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Client   string `json:"client"`
	Phase    string `json:"phase"`
}

func peerIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return host
}
