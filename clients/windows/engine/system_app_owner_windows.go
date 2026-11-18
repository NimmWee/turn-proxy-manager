package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var appIPHelper = windows.NewLazySystemDLL("iphlpapi.dll")
var appTCPTable = appIPHelper.NewProc("GetExtendedTcpTable")
var appUDPTable = appIPHelper.NewProc("GetExtendedUdpTable")
var appTableSlots = make(chan struct{}, 8)

type systemAppEndpoint struct {
	Local, Remote netip.AddrPort
	PID, State    uint32
}

func systemAppEndpoints(ctx context.Context, network string) ([]systemAppEndpoint, error) {
	select {
	case appTableSlots <- struct{}{}:
		defer func() { <-appTableSlots }()
	default:
		return nil, errSystemApp
	}
	proc, class, width := appTCPTable, uintptr(4), 24
	if network == "udp4" {
		proc, class, width = appUDPTable, 1, 12
	} else if network != "tcp4" {
		return nil, errSystemApp
	}
	var size uint32
	code, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, class, 0)
	if code != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) && code != 0 {
		return nil, errSystemApp
	}
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil || size < 4 || size > 4*1024*1024 {
			return nil, errSystemApp
		}
		data := make([]byte, int(size))
		code, _, _ = proc.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(unsafe.Pointer(&size)), 0, windows.AF_INET, class, 0)
		if code == uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if code != 0 || ctx.Err() != nil || size < 4 || int(size) > len(data) {
			return nil, errSystemApp
		}
		data = data[:size]
		count := int(binary.LittleEndian.Uint32(data))
		if count > 65536 || count > (len(data)-4)/width {
			return nil, errSystemApp
		}
		rows := make([]systemAppEndpoint, 0, count)
		address := func(b []byte) netip.AddrPort {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), binary.BigEndian.Uint16(b[4:6]))
		}
		for i := 0; i < count; i++ {
			row := data[4+i*width : 4+(i+1)*width]
			entry := systemAppEndpoint{}
			if network == "tcp4" {
				entry.State = binary.LittleEndian.Uint32(row)
				entry.Local = address(row[4:])
				entry.Remote = address(row[12:])
				entry.PID = binary.LittleEndian.Uint32(row[20:])
			} else {
				entry.Local = address(row)
				entry.PID = binary.LittleEndian.Uint32(row[8:])
			}
			rows = append(rows, entry)
		}
		return rows, nil
	}
	return nil, errSystemApp
}
func systemAppEndpointPID(rows []systemAppEndpoint, network string, source, destination netip.AddrPort) (uint32, error) {
	var pid uint32
	for _, row := range rows {
		if row.Local.Port() != source.Port() {
			continue
		}
		if network == "tcp4" {
			if row.Local != source || row.Remote != destination || row.State < 3 || row.State > 10 {
				continue
			}
		} else if network == "udp4" {
			if row.Local.Addr() != source.Addr() && !row.Local.Addr().IsUnspecified() {
				continue
			}
		} else {
			return 0, errSystemApp
		}
		if row.PID == 0 || pid != 0 && pid != row.PID {
			return 0, errSystemApp
		}
		pid = row.PID
	}
	if pid == 0 {
		return 0, errSystemApp
	}
	return pid, nil
}

func lookupSystemAppOwner(ctx context.Context, network string, source, destination netip.AddrPort) (*systemAppOwner, error) {
	if !source.Addr().Is4() || !destination.Addr().Is4() || source.Port() == 0 || destination.Port() == 0 {
		return nil, errSystemApp
	}
	rows, e := systemAppEndpoints(ctx, network)
	if e != nil {
		return nil, errSystemApp
	}
	pid, e := systemAppEndpointPID(rows, network, source, destination)
	if e != nil {
		return nil, e
	}
	handle, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return nil, errSystemApp
	}
	var creation, exit, kernel, user windows.Filetime
	name := make([]uint16, 1025)
	size := uint32(len(name))
	if windows.QueryFullProcessImageName(handle, 0, &name[0], &size) != nil || windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user) != nil {
		windows.CloseHandle(handle)
		return nil, errSystemApp
	}
	path, e := systemAppPath(windows.UTF16ToString(name[:size]))
	if e != nil {
		windows.CloseHandle(handle)
		return nil, errSystemApp
	}
	o := &systemAppOwner{Path: path, release: func() { windows.CloseHandle(handle) }}
	o.check = func() error {
		state, e := windows.WaitForSingleObject(handle, 0)
		if e != nil || state != uint32(windows.WAIT_TIMEOUT) {
			return errSystemApp
		}
		var now windows.Filetime
		if windows.GetProcessTimes(handle, &now, &exit, &kernel, &user) != nil || now != creation {
			return errSystemApp
		}
		check, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		table, e := systemAppEndpoints(check, network)
		if e != nil {
			return errSystemApp
		}
		current, e := systemAppEndpointPID(table, network, source, destination)
		if e != nil || current != pid {
			return errSystemApp
		}
		state, e = windows.WaitForSingleObject(handle, 0)
		if e != nil || state != uint32(windows.WAIT_TIMEOUT) {
			return errSystemApp
		}
		return nil
	}
	if ctx.Err() != nil || o.Current() != nil {
		o.Close()
		return nil, errSystemApp
	}
	return o, nil
}
