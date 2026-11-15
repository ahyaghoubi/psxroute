//go:build !windows

package gateway

import (
	"errors"
	"net"
	"os"
)

func isElevated() bool { return os.Geteuid() == 0 }

// noIPHelper stands in for Windows' IP Helper API elsewhere.
type noIPHelper struct{}

func newIPHelper() ipHelper { return noIPHelper{} }

var errNotWindows = errors.New("the IP Helper API is Windows only")

func (noIPHelper) Routes() ([]ipRoute, error)     { return nil, errNotWindows }
func (noIPHelper) AddRoute(ipRoute) (bool, error) { return false, errNotWindows }
func (noIPHelper) DeleteRoute(ipRoute) error      { return errNotWindows }
func (noIPHelper) Forwarding(int) (bool, error)   { return false, errNotWindows }

// Interfaces lists the machine's interfaces.
func Interfaces() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Iface, 0, len(ifs))
	for _, i := range ifs {
		it := Iface{Name: i.Name, Index: i.Index, Up: i.Flags&net.FlagUp != 0, MTU: i.MTU}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				it.Addrs = append(it.Addrs, n)
			}
		}
		out = append(out, it)
	}
	return out, nil
}
