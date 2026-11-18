package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"freeturn.local/windows/internal/legacylock"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func upgradeGuard(owner, wanted string, tunnel, broker svc.State) error {
	if owner == "" || owner != wanted {
		return errors.New("UPGRADE_OWNER_MISMATCH")
	}
	if tunnel != svc.Stopped {
		return errors.New("STOP_BEFORE_UPGRADE")
	}
	if broker != svc.Stopped && broker != svc.Running {
		return errors.New("BROKER_TRANSITIONING")
	}
	return nil
}

// No profile/key/owner/options/adapter/route writes belong in upgrade. The
// replacement step may perform the fixed delete-only0.23 WFP migration after
// the old broker exits; rollback never recreates the removed feature.
func performUpgrade(stop, replace, start, restore, restartOld func() error) error {
	if e := stop(); e != nil {
		return e
	}
	e := replace()
	if e == nil {
		e = start()
	}
	if e == nil {
		return nil
	}
	if stop() != nil || restore() != nil || restartOld() != nil {
		return errors.New("UPGRADE_ROLLBACK_FAILED")
	}
	return errors.New("UPGRADE_ROLLED_BACK")
}

func setup(sidText string) error {
	if !isElevated() {
		return errors.New("ADMIN_REQUIRED")
	}
	sid, e := windows.StringToSid(sidText)
	if e != nil || !strings.HasPrefix(sidText, "S-1-5-21-") {
		return errors.New("INVALID_USER_SID")
	}
	if _, _, kind, e := sid.LookupAccount(""); e != nil || kind != windows.SidTypeUser {
		return errors.New("INVALID_USER_SID")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	count := 0
	for _, name := range []string{brokerName, tunnelName} {
		s, e := m.OpenService(name)
		if e == nil {
			count++
			s.Close()
		} else if e != windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return e
		}
	}
	if count == 0 {
		return install(sidText)
	}
	if count != 2 {
		return errors.New("INCOMPLETE_INSTALLATION")
	}
	return upgradeServices(m, sidText)
}

func upgradeServices(m *mgr.Mgr, sidText string) error {
	broker, e := ownService(m, brokerName, "--broker")
	if e != nil {
		return e
	}
	defer broker.Close()
	tunnel, e := ownService(m, tunnelName, "--tunnel")
	if e != nil {
		return e
	}
	defer tunnel.Close()
	for _, s := range []*mgr.Service{broker, tunnel} {
		config, e := s.Config()
		if e != nil || config.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || config.SidType != windows.SERVICE_SID_TYPE_UNRESTRICTED {
			return errors.New("SERVICE_NAME_COLLISION")
		}
	}
	b, e := broker.Query()
	if e != nil {
		return e
	}
	t, e := tunnel.Query()
	if e != nil {
		return e
	}
	dir, e := installDir()
	if e != nil {
		return e
	}
	data, e := dataDir()
	if e != nil {
		return e
	}
	ownerPath := filepath.Join(data, "owner.sid")
	if e = noReparse(ownerPath); e != nil {
		return e
	}
	owner, e := os.ReadFile(ownerPath)
	if e != nil {
		return e
	}
	if e = upgradeGuard(string(owner), sidText, t.State, b.State); e != nil {
		return e
	}
	source, e := os.Executable()
	if e != nil {
		return e
	}
	if strings.EqualFold(filepath.Clean(source), filepath.Join(dir, "FreeTurn.Engine.exe")) {
		return errors.New("UPGRADE_FROM_PACKAGE_REQUIRED")
	}
	nextEngine, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	nextDriver, e := os.ReadFile(filepath.Join(filepath.Dir(source), "wireguard.dll"))
	if e != nil {
		return e
	}
	sum := sha256.Sum256(nextDriver)
	if hex.EncodeToString(sum[:]) != driverHash {
		return errors.New("DRIVER_CHECKSUM")
	}
	if e = secureDirectory(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"); e != nil {
		return e
	}
	enginePath, driverPath := filepath.Join(dir, "FreeTurn.Engine.exe"), filepath.Join(dir, "wireguard.dll")
	for _, path := range []string{enginePath, driverPath} {
		if e = noReparse(path); e != nil {
			return e
		}
	}
	oldEngine, e := os.ReadFile(enginePath)
	if e != nil {
		return e
	}
	oldDriver, e := os.ReadFile(driverPath)
	if e != nil {
		return e
	}
	if b.State == svc.Running && bytes.Equal(oldEngine, nextEngine) && bytes.Equal(oldDriver, nextDriver) {
		return nil
	}
	if e = atomicPrivate(filepath.Join(dir, "FreeTurn.Engine.before-update.exe"), oldEngine); e != nil {
		return e
	}
	if e = atomicPrivate(filepath.Join(dir, "wireguard.before-update.dll"), oldDriver); e != nil {
		return e
	}
	stop := func() error {
		state, e := tunnel.Query()
		if e != nil || state.State != svc.Stopped {
			return errors.New("STOP_BEFORE_UPGRADE")
		}
		current, e := broker.Query()
		if e != nil {
			return e
		}
		var handle windows.Handle
		if current.ProcessId != 0 {
			handle, e = windows.OpenProcess(windows.SYNCHRONIZE, false, current.ProcessId)
			if e != nil {
				return e
			}
			defer windows.CloseHandle(handle)
		}
		if e = stopOwn(m, brokerName, "--broker"); e != nil {
			return e
		}
		if handle != 0 {
			wait, e := windows.WaitForSingleObject(handle, 20000)
			if e != nil || wait != windows.WAIT_OBJECT_0 {
				return errors.New("BROKER_EXIT_TIMEOUT")
			}
		}
		return nil
	}
	start := func() error {
		if e := broker.Start(); e != nil {
			return e
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			state, e := broker.Query()
			if e != nil {
				return e
			}
			if state.State == svc.Running {
				return nil
			}
			if state.State == svc.Stopped {
				return errors.New("BROKER_START_FAILED")
			}
			time.Sleep(100 * time.Millisecond)
		}
		return errors.New("BROKER_START_TIMEOUT")
	}
	replace := func() error {
        // Treat cleanup failure as a replacement failure: performUpgrade can
        // restart the old broker without repeating a failing migration in stop.
        if e=legacylock.Remove();e!=nil{return errors.New("OBSOLETE_NETWORK_RULES_CLEANUP_FAILED")}
		if e := atomicPrivate(enginePath, nextEngine); e != nil {
			return e
		}
		return atomicPrivate(driverPath, nextDriver)
	}
	restore := func() error {
		if e := atomicPrivate(enginePath, oldEngine); e != nil {
			return e
		}
		return atomicPrivate(driverPath, oldDriver)
	}
	restartOld := func() error {
		if b.State == svc.Running {
			return start()
		}
		return nil
	}
	return performUpgrade(stop, replace, start, restore, restartOld)
}
