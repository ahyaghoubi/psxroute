//go:build !darwin

package monitor

import (
	"context"
	"errors"
	"net"
)

// Capture is only implemented on macOS so far.
func Capture(context.Context, string, net.IP, *Monitor) error {
	return errors.New("the connection monitor only works on macOS so far; routing works without it")
}
