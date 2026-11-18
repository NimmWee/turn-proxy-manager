// Package legacylock removes only the obsolete FreeTurn0.23 persistent lock.
// Delete-only migration for explicit elevated setup/uninstall, never status or
// Connect. There is intentionally no API to create/enable firewall objects.
package legacylock

import (
	"errors"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var provider = windows.GUID{Data1: 0xc2a95137, Data2: 0x7c1a, Data3: 0x4ea8, Data4: [8]byte{0xa4, 0x12, 0x65, 0xe1, 0xa0, 0x7e, 0x23, 0x11}}
var sublayer = windows.GUID{Data1: 0xc2a95138, Data2: provider.Data2, Data3: provider.Data3, Data4: provider.Data4}

func filterKey(n uint32) windows.GUID {
	return windows.GUID{Data1: 0xc2a95200 + n, Data2: provider.Data2, Data3: provider.Data3, Data4: provider.Data4}
}
func missing(e error) bool {
	return e == windows.Errno(windows.FWP_E_PROVIDER_NOT_FOUND) || e == windows.Errno(windows.FWP_E_FILTER_NOT_FOUND) || e == windows.Errno(windows.FWP_E_SUBLAYER_NOT_FOUND) || e == windows.Errno(windows.FWP_E_NOT_FOUND)
}

type cleanupOps struct {
	query                   func() (bool, error)
	begin, commit, abort    func() error
	filter, layer, provider func(windows.GUID) error
}

func cleanup(ops cleanupOps) (result error) {
	exists, e := ops.query()
	if e != nil || !exists {
		return e
	}
	if e = ops.begin(); e != nil {
		return e
	}
	committed := false
	defer func() {
		if !committed {
			_ = ops.abort()
		}
	}()
	for n := uint32(1); n <= 256; n++ {
		if e = ops.filter(filterKey(n)); e != nil && !missing(e) {
			return e
		}
	}
	if e = ops.layer(sublayer); e != nil && !missing(e) {
		return e
	}
	if e = ops.provider(provider); e != nil && !missing(e) {
		return e
	}
	if e = ops.commit(); e != nil {
		return e
	}
	committed = true
	return nil
}

var library = windows.NewLazySystemDLL("fwpuclnt.dll")

func call(name string, args ...uintptr) error {
	status, _, _ := syscall.SyscallN(library.NewProc(name).Addr(), args...)
	if status != 0 {
		return windows.Errno(status)
	}
	return nil
}
func Remove() error {
	var h uintptr
	// Non-dynamic session; all writes below are deletes in one transaction.
	if e := call("FwpmEngineOpen0", 0, 10, 0, 0, uintptr(unsafe.Pointer(&h))); e != nil {
		return e
	}
	defer call("FwpmEngineClose0", h)
	remove := func(name string) func(windows.GUID) error {
		return func(key windows.GUID) error { return call(name, h, uintptr(unsafe.Pointer(&key))) }
	}
	return cleanup(cleanupOps{
		query: func() (bool, error) {
			var value unsafe.Pointer
			e := call("FwpmProviderGetByKey0", h, uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(&value)))
			if e == nil {
				if value == nil {
					return false, errors.New("OBSOLETE_RULES_QUERY_FAILED")
				}
				defer call("FwpmFreeMemory0", uintptr(unsafe.Pointer(&value)))
				return true, nil
			}
			if missing(e) {
				return false, nil
			}
			return false, e
		},
		begin: func() error { return call("FwpmTransactionBegin0", h, 0) }, commit: func() error { return call("FwpmTransactionCommit0", h) }, abort: func() error { return call("FwpmTransactionAbort0", h) },
		filter: remove("FwpmFilterDeleteByKey0"), layer: remove("FwpmSubLayerDeleteByKey0"), provider: remove("FwpmProviderDeleteByKey0"),
	})
}
