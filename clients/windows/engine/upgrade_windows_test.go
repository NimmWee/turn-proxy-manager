package main

import (
	"errors"
	"golang.org/x/sys/windows/svc"
	"strings"
	"testing"
)

func TestUpgradeGuardRefusesActiveTunnelAndOwnerChange(t *testing.T) {
	for _, state := range []svc.State{svc.Running, svc.StartPending, svc.StopPending} {
		if upgradeGuard("owner", "owner", state, svc.Running) == nil {
			t.Fatal("active/transitioning tunnel accepted for upgrade")
		}
	}
	if upgradeGuard("owner", "other", svc.Stopped, svc.Running) == nil || upgradeGuard("owner", "owner", svc.Stopped, svc.StopPending) == nil {
		t.Fatal("owner change or unstable broker accepted")
	}
	if upgradeGuard("owner", "owner", svc.Stopped, svc.Running) != nil {
		t.Fatal("stopped owned tunnel rejected")
	}
}
func TestUpgradeRollbackOrderOnReplacementAndStartupFailure(t *testing.T) {
	for _, failure := range []string{"replace", "start", "none"} {
		var order []string
		runningNew := false
		e := performUpgrade(func() error { order = append(order, "stop"); return nil }, func() error {
			order = append(order, "replace")
			runningNew = true
			if failure == "replace" {
				return errors.New("SYNTHETIC")
			}
			return nil
		}, func() error {
			order = append(order, "start")
			if failure == "start" {
				return errors.New("SYNTHETIC")
			}
			return nil
		}, func() error { order = append(order, "restore"); runningNew = false; return nil }, func() error { order = append(order, "restart-old"); return nil })
		if failure == "none" {
			if e != nil || !runningNew || strings.Join(order, ",") != "stop,replace,start" {
				t.Fatal("upgrade sequence failed")
			}
		} else if e == nil || runningNew || strings.Join(order[len(order)-3:], ",") != "stop,restore,restart-old" {
			t.Fatal("failed upgrade did not roll back in order")
		}
	}
}
