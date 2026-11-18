package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

func TestServiceGateRefusesForeignActivePartialBeforeRemoval(t *testing.T) {
	for _, entries := range [][]serviceState{
		{{Present: true, Owned: false, State: svc.Stopped}, {Present: true, Owned: true, State: svc.Stopped}},
		{{Present: true, Owned: true, State: svc.Running}, {Present: true, Owned: true, State: svc.Running}},
		{{Present: true, Owned: true, State: svc.Stopped}, {}},
		{{Present: true, Owned: true, State: svc.StopPending}, {Present: true, Owned: true, State: svc.Stopped}},
	} {
		if serviceGate(entries) == 0 {
			t.Fatal("unsafe state accepted")
		}
	}
	if serviceGate([]serviceState{{}, {}}) != 0 || serviceGate([]serviceState{{Present: true, Owned: true, State: svc.Running}, {Present: true, Owned: true, State: svc.Stopped}}) != 0 {
		t.Fatal("idle broker/no services refused")
	}
}

func TestRemovalGateAllowsOnlyOwnedIdlePartial(t *testing.T) {
	for _, entries := range [][]serviceState{{{Present: true, Owned: true, State: svc.Running}, {}}, {{}, {Present: true, Owned: true, State: svc.Stopped}}} {
		if serviceGate(entries) != 14 || removalGate(entries) != 0 {
			t.Fatal("owned idle partial cannot be explicitly removed")
		}
	}
	for _, entries := range [][]serviceState{{{}, {Present: true, Owned: false, State: svc.Stopped}}, {{}, {Present: true, Owned: true, State: svc.Running}}, {{Present: true, Owned: true, State: svc.StopPending}, {}}} {
		if removalGate(entries) == 0 {
			t.Fatal("foreign/active/transitioning partial accepted")
		}
	}
}

func TestRunCleanupTouchesOnlyExactOwnedTestValue(t *testing.T) {
	var nonce [12]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		t.Fatal("fixture nonce")
	}
	path := `Software\FreeTurnSetupCheck_` + hex.EncodeToString(nonce[:])
	if !strings.HasPrefix(path, `Software\FreeTurnSetupCheck_`) {
		t.Fatal("unsafe fixture path")
	}
	key, _, e := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if e != nil {
		t.Fatal("fixture create")
	}
	t.Cleanup(func() { key.Close(); registry.DeleteKey(registry.CURRENT_USER, path) })
	app := `C:\Program Files\FreeTurn\FreeTurn.Windows.exe`
	foreign := `"C:\Other\FreeTurn.Windows.exe" --start-hidden`
	if key.SetStringValue("FreeTurnManagerUI", foreign) != nil {
		t.Fatal("fixture set")
	}
	if clearRunValue(registry.CURRENT_USER, path, app) != nil {
		t.Fatal("foreign check")
	}
	if got, _, e := key.GetStringValue("FreeTurnManagerUI"); e != nil || got != foreign {
		t.Fatal("foreign startup value changed")
	}
	if key.SetStringValue("FreeTurnManagerUI", `"`+app+`" --start-hidden`) != nil {
		t.Fatal("fixture set")
	}
	if clearRunValue(registry.CURRENT_USER, path, app) != nil {
		t.Fatal("owned removal")
	}
	if _, _, e := key.GetStringValue("FreeTurnManagerUI"); e != registry.ErrNotExist {
		t.Fatal("owned startup value not removed")
	}
}

func TestProtectedCodeACLRejectsNonAdminWriters(t *testing.T) {
	for _, sddl := range []string{"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)", "D:P(A;;FA;;;SY)(A;;FA;;;BA)"} {
		sd, e := windows.SecurityDescriptorFromString(sddl)
		if e != nil || safeDACL(sd) != nil {
			t.Fatal("protected ACL rejected")
		}
	}
	for _, sddl := range []string{"D:P(A;;FA;;;WD)", "D:P(A;;FA;;;SY)(A;;GW;;;BU)", "D:P(A;;WD;;;AU)", "D:NO_ACCESS_CONTROL"} {
		sd, e := windows.SecurityDescriptorFromString(sddl)
		if e == nil && safeDACL(sd) == nil {
			t.Fatal("untrusted writer accepted")
		}
	}
}

func TestOwnedMarkerAndReparseGuard(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "FreeTurn")
	if checkInstallFolder(target, false) != 0 {
		t.Fatal("new directory refused")
	}
	if os.Mkdir(target, 0700) != nil {
		t.Fatal("fixture mkdir")
	}
	if checkInstallFolder(target, false) == 0 {
		t.Fatal("foreign folder adopted")
	}
	if os.WriteFile(filepath.Join(target, markerName), []byte(markerText), 0600) != nil {
		t.Fatal("fixture marker")
	}
	if checkInstallFolder(target, false) != 0 {
		t.Fatal("owned marker refused")
	}
	if os.WriteFile(filepath.Join(target, markerName), []byte("foreign"), 0600) != nil {
		t.Fatal("fixture marker")
	}
	if checkInstallFolder(target, false) == 0 {
		t.Fatal("foreign marker accepted")
	}
}

func TestRemovalOrderingAndStartupExactOwnership(t *testing.T) {
	for _, fail := range []string{"core", "verify", "none"} {
		var order []string
		step := func(name string) func() error {
			return func() error {
				order = append(order, name)
				if name == fail {
					return errors.New("synthetic")
				}
				return nil
			}
		}
		err := removeSequence(step("core"), step("verify"), step("startup"), step("files"))
		if fail == "core" && (len(order) != 1 || err == nil) || fail == "verify" && (len(order) != 2 || err == nil) || fail == "none" && (len(order) != 4 || err != nil) {
			t.Fatal("cleanup ran after unconfirmed removal")
		}
	}
	path := `C:\Program Files\FreeTurn\FreeTurn.Windows.exe`
	if !ownedStartup(`"C:\Program Files\FreeTurn\FreeTurn.Windows.exe" --start-hidden`, path) {
		t.Fatal("owned startup refused")
	}
	for _, command := range []string{`"C:\Other\FreeTurn.Windows.exe" --start-hidden`, `"C:\Program Files\FreeTurn\FreeTurn.Windows.exe" --unsafe`, `C:\Program Files\FreeTurn\FreeTurn.Windows.exe --start-hidden`} {
		if ownedStartup(command, path) {
			t.Fatal("foreign startup accepted")
		}
	}
}
