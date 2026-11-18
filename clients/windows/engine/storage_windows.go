package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
)

const privateACL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func dataDir() (string, error) {
	p, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	return filepath.Join(p, "FreeTurnManager"), e
}
func installDir() (string, error) {
	p, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	return filepath.Join(p, "FreeTurnManager"), e
}

// Explicit Windows DACLs, not os.Chmod (which does not protect Windows files).
// Reject junctions rather than following an attacker-selected storage path.
func secureDirectory(path, sddl string) error {
	sd, e := windows.SecurityDescriptorFromString("O:BA" + sddl)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	e = windows.CreateDirectory(p, &sa)
	if e != nil && e != windows.ERROR_ALREADY_EXISTS {
		return e
	}
	h, e := windows.CreateFile(p, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("UNSAFE_DIRECTORY")
	}
	current, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	owner, _, e := current.Owner()
	if e != nil || !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return errors.New("UNTRUSTED_DIRECTORY_OWNER")
	}
	return windows.SetKernelObjectSecurity(h, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, sd)
}

func noReparse(path string) error {
	i, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if i.Mode()&os.ModeSymlink != 0 || !i.Mode().IsRegular() {
		return errors.New("UNSAFE_FILE")
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	a, e := windows.GetFileAttributes(p)
	if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("UNSAFE_FILE")
	}
	return nil
}

func atomicPrivate(path string, data []byte) error {
	if e := noReparse(path); e != nil {
		return e
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return e
	}
	name := filepath.Join(filepath.Dir(path), ".ftm-"+hex.EncodeToString(nonce[:]))
	// Set ownership at creation. Merely removing an installer's user ACE is
	// insufficient: an unelevated owner could otherwise rewrite the DACL of a
	// SYSTEM service executable after UAC installation.
	ownerACL := "O:BA" + privateACL
	if !isElevated() && requireSystem() != nil {
		t, e := windows.OpenCurrentProcessToken()
		if e != nil {
			return e
		}
		u, e := t.GetTokenUser()
		t.Close()
		if e != nil {
			return e
		}
		sid := u.User.Sid.String()
		ownerACL = "O:" + sid + "D:P(A;;FA;;;" + sid + ")"
	}
	sd, e := windows.SecurityDescriptorFromString(ownerACL)
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	utf16, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return e
	}
	h, e := windows.CreateFile(utf16, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), name)
	defer os.Remove(name)
	if _, e = f.Write(data); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	from, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return e
	}
	to, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func writeSecret(path, name string, data []byte) error {
	b, e := dpapi.Encrypt(data, name)
	if e != nil {
		return e
	}
	return atomicPrivate(path, b)
}
func readSecret(path, name string) ([]byte, error) {
	if e := noReparse(path); e != nil {
		return nil, e
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) > maxSystemMessage*2 {
		return nil, errors.New("STORAGE_INVALID")
	}
	return dpapi.Decrypt(b, name)
}
