// Setup-only helper. Read checks never create services, files or network state.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const markerName = ".freeturn-setup-v1"
const markerText = "FreeTurn desktop setup v1\n"
const helperName = "FreeTurn.SetupGuard.exe"
const appName = "FreeTurn.Windows.exe"

var codes = map[int]string{0: "READY", 10: "UI_RUNNING", 11: "VPN_ACTIVE", 12: "SERVICE_COLLISION", 13: "STATE_UNAVAILABLE", 14: "PARTIAL_SERVICES", 15: "UNSAFE_PATH", 16: "FOREIGN_INSTALL", 17: "ELEVATED_INSTALLED_HELPER_REQUIRED", 18: "CORE_REMOVE_FAILED", 19: "OWNED_CLEANUP_FAILED", 2: "INVALID_OPERATION"}

type serviceState struct {
	Present, Owned bool
	State          svc.State
}

// Entries are ordered broker,tunnel. No upgrade/uninstall may kill an active VPN.
func serviceGate(entries []serviceState) int {
	if len(entries) != 2 {
		return 13
	}
	count := 0
	for _, entry := range entries {
		if entry.Present {
			count++
			if !entry.Owned {
				return 12
			}
		}
	}
	if count == 0 {
		return 0
	}
	if count != 2 {
		return 14
	}
	if entries[1].State != svc.Stopped {
		return 11
	}
	if entries[0].State != svc.Stopped && entries[0].State != svc.Running {
		return 13
	}
	return 0
}

// Explicit uninstall may remove a confirmed owned idle partial installation;
// install/upgrade still refuses it. Foreign or live entries always stop first.
func removalGate(entries []serviceState) int {
	if len(entries) != 2 {
		return 13
	}
	for _, entry := range entries {
		if entry.Present && !entry.Owned {
			return 12
		}
	}
	if entries[1].Present && entries[1].State != svc.Stopped {
		return 11
	}
	if entries[0].Present && entries[0].State != svc.Stopped && entries[0].State != svc.Running {
		return 13
	}
	return 0
}

func removableServices() ([]serviceState, int) {
	entries, code := services()
	if code == 14 {
		code = removalGate(entries)
	}
	return entries, code
}

func programFolders() (string, string, error) {
	root, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	return filepath.Join(root, "FreeTurn"), filepath.Join(root, "FreeTurnManager"), e
}

func noReparseChain(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		p, e := windows.UTF16PtrFromString(current)
		if e != nil {
			return e
		}
		attributes, e := windows.GetFileAttributes(p)
		if e != nil && e != windows.ERROR_FILE_NOT_FOUND && e != windows.ERROR_PATH_NOT_FOUND {
			return e
		}
		if e == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("unsafe")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func protectedDirectory(path string) error { return protectedObject(path, true) }

func safeDACL(sd *windows.SECURITY_DESCRIPTOR) error {
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount > 128 {
		return errors.New("acl")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return errors.New("ace")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("ace type")
		}
		const write = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40 /* FILE_DELETE_CHILD */ | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER
		if uint32(ace.Mask)&write == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !sid.IsWellKnown(windows.WinLocalSystemSid) && sid.String() != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
			return errors.New("writable")
		}
	}
	return nil
}

func protectedObject(path string, directory bool) error {
	if noReparseChain(path) != nil {
		return errors.New("unsafe")
	}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	h, e := windows.CreateFile(p, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("unsafe")
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("owner")
	}
	return safeDACL(sd)
}

func checkInstallFolder(path string, protected bool) int {
	if noReparseChain(path) != nil {
		return 15
	}
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return 0
	}
	if e != nil || !info.IsDir() {
		return 15
	}
	if protected && protectedDirectory(path) != nil {
		return 15
	}
	marker := filepath.Join(path, markerName)
	if noReparseChain(marker) != nil {
		return 15
	}
	file, e := os.Open(marker)
	if e != nil {
		return 16
	}
	defer file.Close()
	raw, e := io.ReadAll(io.LimitReader(file, 128))
	if e != nil || string(raw) != markerText {
		return 16
	}
	return 0
}

func services() (entries []serviceState, code int) {
	_, core, e := programFolders()
	if e != nil {
		return nil, 13
	}
	h, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, 13
	}
	defer windows.CloseServiceHandle(h)
	for _, item := range []struct{ name, mode string }{{"FreeTurnManager", "--broker"}, {"WireGuardTunnel$FTM", "--tunnel"}} {
		name, _ := windows.UTF16PtrFromString(item.name)
		handle, e := windows.OpenService(h, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
		if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			entries = append(entries, serviceState{})
			continue
		}
		if e != nil {
			return nil, 13
		}
		s := mgr.Service{Name: item.name, Handle: handle}
		config, ce := s.Config()
		state, se := s.Query()
		s.Close()
		if ce != nil || se != nil {
			return nil, 13
		}
		expected := windows.EscapeArg(filepath.Join(core, "FreeTurn.Engine.exe")) + " " + item.mode
		entries = append(entries, serviceState{true, strings.EqualFold(config.BinaryPathName, expected) && strings.EqualFold(config.ServiceStartName, "LocalSystem") && config.ServiceType == windows.SERVICE_WIN32_OWN_PROCESS && config.SidType == windows.SERVICE_SID_TYPE_UNRESTRICTED, state.State})
	}
	return entries, serviceGate(entries)
}

func uiRunning() (bool, error) {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return false, e
	}
	defer windows.CloseHandle(h)
	entry := windows.ProcessEntry32{Size: uint32(unsafeProcessEntrySize())}
	e = windows.Process32First(h, &entry)
	for e == nil {
		if strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), appName) {
			return true, nil
		}
		e = windows.Process32Next(h, &entry)
	}
	if e != windows.ERROR_NO_MORE_FILES {
		return false, e
	}
	return false, nil
}

func preflight(uninstall bool) int {
	app, _, e := programFolders()
	if e != nil {
		return 15
	}
	if code := checkInstallFolder(app, true); code != 0 {
		return code
	}
	if uninstall {
		if _, e := os.Stat(filepath.Join(app, markerName)); e != nil {
			return 16
		}
	}
	active, e := uiRunning()
	if e != nil {
		return 13
	}
	if active {
		return 10
	}
	if uninstall {
		entries, code := removableServices()
		if code != 0 {
			return code
		}
		if (entries[0].Present || entries[1].Present) && coreMetadata() != nil {
			return 16
		}
		return 0
	}
	_, code := services()
	return code
}

func ownedStartup(command, path string) bool {
	return strings.EqualFold(command, `"`+path+`" --start-hidden`)
}

// Read first, request write access only after exact ownership is established.
// Unreadable foreign hives are left alone; loaded owned values are rechecked.
func clearRunValue(root registry.Key, path, app string) error {
	read, e := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if e == registry.ErrNotExist || e == windows.ERROR_PATH_NOT_FOUND || e == windows.ERROR_ACCESS_DENIED {
		return nil
	}
	if e != nil {
		return e
	}
	command, kind, e := read.GetStringValue("FreeTurnManagerUI")
	read.Close()
	if e == registry.ErrNotExist || e == registry.ErrUnexpectedType || e == windows.ERROR_ACCESS_DENIED {
		return nil
	}
	if e != nil {
		return e
	}
	if kind != registry.SZ || !ownedStartup(command, app) {
		return nil
	}
	write, e := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if e == registry.ErrNotExist || e == windows.ERROR_PATH_NOT_FOUND {
		return nil
	}
	if e != nil {
		return e
	}
	defer write.Close()
	command, kind, e = write.GetStringValue("FreeTurnManagerUI")
	if e == registry.ErrNotExist || e == registry.ErrUnexpectedType {
		return nil
	}
	if e != nil {
		return e
	}
	if kind == registry.SZ && ownedStartup(command, app) {
		e = write.DeleteValue("FreeTurnManagerUI")
		if e != registry.ErrNotExist {
			return e
		}
	}
	return nil
}

func clearOwnedStartup(app string) error {
	root, e := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if e != nil {
		return e
	}
	defer root.Close()
	names, e := root.ReadSubKeyNames(1025)
	if e != nil && e != io.EOF {
		return e
	}
	if len(names) > 1024 {
		return errors.New("hives")
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "S-1-5-21-") {
			continue
		}
		if _, e := windows.StringToSid(name); e != nil {
			continue
		}
		if e := clearRunValue(registry.USERS, name+`\Software\Microsoft\Windows\CurrentVersion\Run`, filepath.Join(app, appName)); e != nil {
			return e
		}
	}
	return nil
}

func removeSequence(core, verify, startup, files func() error) error {
	for _, step := range []func() error{core, verify, startup, files} {
		if e := step(); e != nil {
			return e
		}
	}
	return nil
}

func coreAbsent() error {
	for attempt := 0; attempt < 25; attempt++ {
		entries, code := services()
		if code == 0 && !entries[0].Present && !entries[1].Present {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errors.New("services")
}

func coreMetadata() error {
	data, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return e
	}
	ownerPath := filepath.Join(data, "FreeTurnManager", "owner.sid")
	if protectedDirectory(filepath.Dir(ownerPath)) != nil {
		return errors.New("core metadata directory")
	}
	if protectedObject(ownerPath, false) != nil {
		return errors.New("core ownership metadata")
	}
	ownerFile, e := os.Open(ownerPath)
	if e != nil {
		return e
	}
	defer ownerFile.Close()
	owner, e := io.ReadAll(io.LimitReader(ownerFile, 257))
	if e != nil || len(owner) > 256 || !strings.HasPrefix(string(owner), "S-1-5-21-") {
		return errors.New("core owner")
	}
	if _, e := windows.StringToSid(string(owner)); e != nil {
		return errors.New("core owner")
	}
	return nil
}

func cleanCoreFiles(core string) error {
	if _, e := os.Stat(core); os.IsNotExist(e) {
		return nil
	}
	if e := protectedDirectory(core); e != nil {
		return e
	}
	if e := coreMetadata(); e != nil {
		return e
	}
	names := []string{"FreeTurn.Engine.exe", "wireguard.dll", "FreeTurn.Engine.before-update.exe", "wireguard.before-update.dll"}
	for _, name := range names {
		path := filepath.Join(core, name)
		if noReparseChain(path) != nil {
			return errors.New("unsafe")
		}
		if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
			return errors.New("type")
		} else if e != nil && !os.IsNotExist(e) {
			return e
		}
		if _, e := os.Stat(path); e == nil && protectedObject(path, false) != nil {
			return errors.New("core file ownership")
		}
	}
	for _, name := range names {
		if e := os.Remove(filepath.Join(core, name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	if e := os.Remove(core); e != nil && !os.IsNotExist(e) && !errors.Is(e, windows.ERROR_DIR_NOT_EMPTY) {
		return e
	}
	return nil
}

func removeServices() int {
	app, core, e := programFolders()
	if e != nil {
		return 17
	}
	self, e := os.Executable()
	if e != nil || !strings.EqualFold(filepath.Clean(self), filepath.Join(app, helperName)) || protectedObject(self, false) != nil {
		return 17
	}
	var token windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
		return 17
	}
	defer token.Close()
	if !token.IsElevated() {
		return 17
	}
	if code := preflight(true); code != 0 {
		return code
	}
	err := removeSequence(func() error {
		entries, code := removableServices()
		if code != 0 {
			return errors.New("state")
		}
		if !entries[0].Present && !entries[1].Present {
			return nil
		}
		if protectedDirectory(core) != nil || protectedObject(filepath.Join(core, "FreeTurn.Engine.exe"), false) != nil {
			return errors.New("source")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, filepath.Join(core, "FreeTurn.Engine.exe"), "--uninstall")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	}, coreAbsent, func() error { return clearOwnedStartup(app) }, func() error { return cleanCoreFiles(core) })
	if err != nil {
		return 18
	}
	return 0
}

func main() {
	code := 2
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "--check-install":
			code = preflight(false)
		case "--check-uninstall":
			code = preflight(true)
		case "--remove-services":
			code = removeServices()
		}
	}
	report := map[string]any{"ok": code == 0, "code": codes[code], "readOnly": len(os.Args) == 2 && os.Args[1] != "--remove-services"}
	if len(os.Args) == 2 && (os.Args[1] == "--check-install" || os.Args[1] == "--check-uninstall") {
		report["networkChanged"] = false
	}
	json.NewEncoder(os.Stdout).Encode(report)
	os.Exit(code)
}
