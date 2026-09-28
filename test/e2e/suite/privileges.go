package suite

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func checkPrivileges(dir, id string) error {
	for name, uid := range map[string]int{"probe": 10000, "runtime": 2000} {
		data, err := os.ReadFile(filepath.Join(dir, name+"-privileges.json"))
		if err != nil {
			return err
		}
		var p struct {
			ID                                             string
			UIDBefore, GIDBefore, UIDAfter, GIDAfter       int
			SetUIDDenied, SetGIDDenied, NetworkAdminDenied bool
		}
		if err = json.Unmarshal(data, &p); err != nil {
			return err
		}
		if p.ID != id || p.UIDBefore != uid || p.GIDBefore != uid || p.UIDAfter != uid || p.GIDAfter != uid || !p.SetUIDDenied || !p.SetGIDDenied || !p.NetworkAdminDenied {
			return fmt.Errorf("%s: restricted privilege envelope failed", name)
		}
	}
	return nil
}
