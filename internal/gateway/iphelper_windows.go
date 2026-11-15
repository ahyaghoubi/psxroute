//go:build windows

package gateway

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardEntry = iphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2    = iphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2    = iphlpapi.NewProc("DeleteIpForwardEntry2")
)

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

type winIPHelper struct{}

func newIPHelper() ipHelper { return winIPHelper{} }

func sockaddr4(ip net.IP) windows.RawSockaddrInet {
	var sa windows.RawSockaddrInet
	sa.Family = windows.AF_INET
	if v4 := ip.To4(); v4 != nil {
		// SOCKADDR_IN: family, port, then the address in network order.
		copy((*[4]byte)(unsafe.Pointer(&sa.Data[0]))[:], v4)
	}
	return sa
}

func ip4(sa *windows.RawSockaddrInet) net.IP {
	b := (*[4]byte)(unsafe.Pointer(&sa.Data[0]))
	return net.IPv4(b[0], b[1], b[2], b[3]).To4()
}

func (winIPHelper) row(r ipRoute) *windows.MibIpForwardRow2 {
	var row windows.MibIpForwardRow2
	_, _, _ = procInitializeIpForwardEntry.Call(uintptr(unsafe.Pointer(&row)))
	row.InterfaceIndex = uint32(r.IfIndex)
	row.DestinationPrefix.Prefix = sockaddr4(r.Dst.IP)
	ones, _ := r.Dst.Mask.Size()
	row.DestinationPrefix.PrefixLength = uint8(ones)
	row.NextHop = sockaddr4(r.NextHop)
	row.Metric = r.Metric
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	return &row
}

func (winIPHelper) Routes() ([]ipRoute, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	var out []ipRoute
	for _, row := range table.Rows() {
		if row.DestinationPrefix.Prefix.Family != windows.AF_INET {
			continue
		}
		mask := net.CIDRMask(int(row.DestinationPrefix.PrefixLength), 32)
		out = append(out, ipRoute{
			Dst:     &net.IPNet{IP: ip4(&row.DestinationPrefix.Prefix).Mask(mask), Mask: mask},
			IfIndex: int(row.InterfaceIndex),
			NextHop: ip4(&row.NextHop),
			Metric:  row.Metric,
		})
	}
	return out, nil
}

func (h winIPHelper) AddRoute(r ipRoute) (bool, error) {
	ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(h.row(r))))
	switch err := windows.Errno(ret); {
	case ret == 0:
		return true, nil
	case errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS):
		return false, nil
	default:
		return false, err
	}
}

func (h winIPHelper) DeleteRoute(r ipRoute) error {
	ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(h.row(r))))
	switch err := windows.Errno(ret); {
	case ret == 0, errors.Is(err, windows.ERROR_NOT_FOUND), errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return nil
	default:
		return err
	}
}

func (winIPHelper) Forwarding(ifIndex int) (bool, error) {
	row := windows.MibIpInterfaceRow{Family: windows.AF_INET, InterfaceIndex: uint32(ifIndex)}
	if err := windows.GetIpInterfaceEntry(&row); err != nil {
		return false, err
	}
	return row.ForwardingEnabled != 0, nil
}

// Interfaces lists the machine's adapters by their friendly names, with the
// description and type that tell a VPN adapter from a network card.
func Interfaces() ([]Iface, error) {
	size := uint32(15000)
	var buf []byte
	for range 3 {
		buf = make([]byte, size)
		err := windows.GetAdaptersAddresses(windows.AF_INET, windows.GAA_FLAG_INCLUDE_PREFIX,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return nil, err
		}
		buf = nil
	}
	if buf == nil {
		return nil, errors.New("couldn't list network adapters")
	}
	var out []Iface
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		it := Iface{
			Name:  windows.UTF16PtrToString(aa.FriendlyName),
			Desc:  windows.UTF16PtrToString(aa.Description),
			Index: int(aa.IfIndex),
			Up:    aa.OperStatus == windows.IfOperStatusUp,
			MTU:   int(aa.Mtu),
			// PPP covers Windows' own VPN connections; Wintun registers as
			// a proprietary virtual adapter (53).
			Virtual: aa.IfType == windows.IF_TYPE_PPP || aa.IfType == windows.IF_TYPE_TUNNEL || aa.IfType == 53,
		}
		for ua := aa.FirstUnicastAddress; ua != nil; ua = ua.Next {
			ip := ua.Address.IP().To4()
			if ip == nil {
				continue
			}
			it.Addrs = append(it.Addrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(int(ua.OnLinkPrefixLength), 32)})
		}
		out = append(out, it)
	}
	return out, nil
}
