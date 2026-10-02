//go:build !linux

package main

import (
	"context"
	"errors"
	"flag"
)

func capture(context.Context, *flag.FlagSet, []string) error {
	return errors.New("capture requires the owned Linux receiver network namespace")
}

func traceDrops(context.Context, *flag.FlagSet, []string) error {
	return errors.New("drop observation requires the owned Linux node")
}

func privileges(*flag.FlagSet, []string) error {
	return errors.New("privilege acceptance requires Linux")
}

func protocolRequest(context.Context, *observation) error {
	return errors.New("IP protocol probes require Linux")
}

func protocolListener(context.Context, string, string) (func() error, error) {
	return nil, errors.New("IP protocol receivers require Linux")
}

func networkState(context.Context, *flag.FlagSet, []string) error {
	return errors.New("network state requires Linux")
}
