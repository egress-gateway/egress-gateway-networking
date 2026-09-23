package suite

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Existing gateway connections may finish during the next receiver observation.
// Only the precise pre-probe NAT tuple of the owned gateway is unrelated traffic;
// a node IP alone cannot distinguish that traffic from a protected Pod bypass.
func gatewayBackgroundFlow(dir, id, source string, packet probeRecord) (bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, "gateway-flow-owner.json"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var owner struct{ ID, Namespace, UID, IP, ServiceAccount, Destination string }
	if err = json.Unmarshal(data, &owner); err != nil {
		return false, err
	}
	if owner.ID != id || owner.Namespace != "networking-gateway" || owner.ServiceAccount != "gateway" || owner.UID == "" || net.ParseIP(owner.IP) == nil || owner.IP == source || packet.Protocol != "tcp" || packet.Destination != owner.Destination {
		return false, nil
	}
	host, port, err := net.SplitHostPort(owner.Destination)
	if err != nil {
		return false, err
	}
	data, err = os.ReadFile(filepath.Join(dir, "gateway-conntrack-before.txt"))
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "tcp" {
			continue
		}
		values := map[string][]string{}
		for _, field := range fields {
			key, value, ok := strings.Cut(field, "=")
			if ok {
				values[key] = append(values[key], value)
			}
		}
		complete := true
		for _, key := range []string{"src", "dst", "sport", "dport"} {
			complete = complete && len(values[key]) == 2
		}
		if !complete || values["src"][0] != owner.IP || values["dst"][0] != host || values["dport"][0] != port || values["src"][1] != host || values["sport"][1] != port {
			continue
		}
		valid := true
		for _, key := range []string{"sport", "dport"} {
			for _, p := range values[key] {
				n, e := strconv.ParseUint(p, 10, 16)
				valid = valid && e == nil && n != 0
			}
		}
		if !valid || net.ParseIP(values["dst"][1]) == nil {
			continue
		}
		if packet.Remote == net.JoinHostPort(values["dst"][1], values["dport"][1]) {
			return true, nil
		}
	}
	return false, nil
}
