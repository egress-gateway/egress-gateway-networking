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
