package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreshInstallCannotAdoptAnotherOwnersRetainedProfile(t *testing.T) {
	root := t.TempDir()
	wanted := "S-1-5-21-11-22-33-1001"
	other := "S-1-5-21-11-22-33-1002"
	if existingOwnerBeforeInstall(root, wanted) != nil {
		t.Fatal("empty fresh storage refused")
	}
	profile := filepath.Join(root, "profile.dpapi")
	original := []byte("SYNTHETIC_RETAINED_PRIVATE_DATA")
	if os.WriteFile(profile, original, 0600) != nil {
		t.Fatal("fixture profile")
	}
	if e := existingOwnerBeforeInstall(root, wanted); e == nil || e.Error() != "INCOMPLETE_INSTALLATION" {
		t.Fatal("unowned retained data silently adopted")
	}
	owner := filepath.Join(root, "owner.sid")
	if os.WriteFile(owner, []byte(wanted), 0600) != nil {
		t.Fatal("fixture owner")
	}
	if existingOwnerBeforeInstall(root, wanted) != nil {
		t.Fatal("same owner cannot reinstall preserved profile")
	}
	if e := existingOwnerBeforeInstall(root, other); e == nil || e.Error() != "UPGRADE_OWNER_MISMATCH" {
		t.Fatal("another Windows user may adopt retained machine DPAPI profile")
	}
	got, e := os.ReadFile(profile)
	if e != nil || string(got) != string(original) {
		t.Fatal("refused ownership changed retained profile")
	}
	got, e = os.ReadFile(owner)
	if e != nil || string(got) != wanted {
		t.Fatal("refused ownership rewrote owner")
	}
}
