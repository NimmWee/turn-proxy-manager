package legacylock

import (
	"errors"
	"golang.org/x/sys/windows"
	"testing"
)

func TestNoProviderMeansNoWrites(t *testing.T) {
	writes := 0
	ops := cleanupOps{query: func() (bool, error) { return false, nil }, begin: func() error { writes++; return nil }}
	if e := cleanup(ops); e != nil || writes != 0 {
		t.Fatal("absent provider must be a successful read-only no-op")
	}
	if !missing(windows.Errno(windows.FWP_E_PROVIDER_NOT_FOUND)) || missing(windows.ERROR_ACCESS_DENIED) {
		t.Fatal("incorrect WFP absence/access classification")
	}
}
func TestOnlyFixedOwnedObjectsRemovedInTransaction(t *testing.T) {
	keys := map[windows.GUID]bool{}
	commits, aborts, stages := 0, 0, 0
	ops := cleanupOps{query: func() (bool, error) { return true, nil }, begin: func() error { return nil }, filter: func(key windows.GUID) error {
		if key == provider || key == sublayer || keys[key] {
			t.Fatal("invalid/duplicate filter key")
		}
		keys[key] = true
		return windows.Errno(windows.FWP_E_FILTER_NOT_FOUND)
	}, layer: func(key windows.GUID) error {
		if key != sublayer || len(keys) != 256 {
			t.Fatal("foreign layer/order")
		}
		stages++
		return nil
	}, provider: func(key windows.GUID) error {
		if key != provider || stages != 1 {
			t.Fatal("foreign provider/order")
		}
		stages++
		return nil
	}, commit: func() error { commits++; return nil }, abort: func() error { aborts++; return nil }}
	if e := cleanup(ops); e != nil || commits != 1 || aborts != 0 || stages != 2 {
		t.Fatal("cleanup did not commit owned objects")
	}
	deny := errors.New("synthetic access denial")
	ops.filter = func(windows.GUID) error { return deny }
	if e := cleanup(ops); !errors.Is(e, deny) || commits != 1 || aborts != 1 {
		t.Fatal("partial cleanup not rolled back")
	}
	ops.filter = func(key windows.GUID) error { keys[key] = true; return nil }
	ops.commit = func() error { return deny }
	stages = 0
	keys = map[windows.GUID]bool{}
	if e := cleanup(ops); !errors.Is(e, deny) || aborts != 2 {
		t.Fatal("failed commit not rolled back")
	}
}
