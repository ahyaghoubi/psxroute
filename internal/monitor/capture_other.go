//go:build !darwin

package monitor

import (
	"context"
	"errors"
	"net"
)

// Capture is only implemented on macOS, alongside gateway mode.
func Capture(context.Context, string, net.IP, *Monitor) error {
	return errors.New("the connection monitor needs gateway mode, which is macOS only so far")
}
