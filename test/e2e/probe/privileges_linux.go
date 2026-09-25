package main

import (
	"errors"
	"flag"
	"os"

	"golang.org/x/sys/unix"
)

// Operates only in the restricted application process. A successful forbidden
// operation is evidence of failure, never a reason to continue privileged work.
func privileges(f *flag.FlagSet, args []string) error {
	id := f.String("id", "", "correlation")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("id required")
	}
	uid, gid := os.Getuid(), os.Getgid()
	gidErr := unix.Setgid(1337)
	uidErr := unix.Setuid(1337)
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// SO_MARK requires network administration (or CAP_NET_RAW on newer kernels),
	// both absent from the enrollment application envelope. It changes no rules.
	markErr := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 1)
	emit(map[string]any{"ID": *id, "UIDBefore": uid, "GIDBefore": gid, "UIDAfter": os.Getuid(), "GIDAfter": os.Getgid(), "SetUIDDenied": errors.Is(uidErr, unix.EPERM), "SetGIDDenied": errors.Is(gidErr, unix.EPERM), "NetworkAdminDenied": errors.Is(markErr, unix.EPERM)})
	return nil
}
