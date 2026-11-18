package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
)

// No service/adapter creation, network dialing, key reads or settings changes.
func preflight() map[string]any {
	exe, e := os.Executable()
	driverOK := false
	if e == nil {
		data, e := os.ReadFile(filepath.Join(filepath.Dir(exe), "wireguard.dll"))
		if e == nil {
			sum := sha256.Sum256(data)
			driverOK = hex.EncodeToString(sum[:]) == driverHash
		}
	}
	_, uplinkError := selectUnderlay()
	uplinkStatus := "ready"
	if uplinkError != nil {
		uplinkStatus = "unavailable"
		switch uplinkError.Error() {
		case "OTHER_VPN_OR_NONPHYSICAL_UPLINK", "NO_IPV4_PHYSICAL_UPLINK":
			uplinkStatus = uplinkError.Error()
		}
	}
	return map[string]any{"ok": driverOK && uplinkError == nil && runtime.GOARCH == "amd64", "architecture": runtime.GOARCH, "driverChecksum": driverOK, "physicalIPv4Uplink": uplinkError == nil, "uplinkStatus": uplinkStatus, "networkChanges": false}
}
