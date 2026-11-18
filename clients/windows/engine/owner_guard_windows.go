package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Uninstall deliberately retains SYSTEM-encrypted data. A later fresh install
// must not rebind that data to another Windows SID merely because SCM is empty.
// This read-only gate runs before directory/ACL/rule/service mutations.
func existingOwnerBeforeInstall(data, wanted string) error {
	info, e := os.Lstat(data)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return errors.New("INCOMPLETE_INSTALLATION")
	}
	p, e := windows.UTF16PtrFromString(data)
	if e != nil {
		return errors.New("UNSAFE_DIRECTORY")
	}
	attributes, e := windows.GetFileAttributes(p)
	if e != nil || !info.IsDir() || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("UNSAFE_DIRECTORY")
	}
	ownerPath := filepath.Join(data, "owner.sid")
	if noReparse(ownerPath) != nil {
		return errors.New("INCOMPLETE_INSTALLATION")
	}
	file, e := os.Open(ownerPath)
	if os.IsNotExist(e) {
		entries, e := os.ReadDir(data)
		if e != nil || len(entries) != 0 {
			return errors.New("INCOMPLETE_INSTALLATION")
		}
		return nil
	}
	if e != nil {
		return errors.New("INCOMPLETE_INSTALLATION")
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, 257))
	if e != nil || len(raw) == 0 || len(raw) > 256 || !strings.HasPrefix(string(raw), "S-1-5-21-") {
		return errors.New("INCOMPLETE_INSTALLATION")
	}
	if _, e := windows.StringToSid(string(raw)); e != nil {
		return errors.New("INCOMPLETE_INSTALLATION")
	}
	if string(raw) != wanted {
		return errors.New("UPGRADE_OWNER_MISMATCH")
	}
	return nil
}
