//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/samosvalishe/free-turn-proxy/mobile"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/tunnel"
)

// Keeping the official tunnel and FreeTurn in the same image is intentional:
// WireGuard's firewall exception is process-specific. No VPN starts by default.
var officialTunnel = tunnel.Run

const engineVersion = "0.27.0"

func main() {
	mobile.SetLogBuffer(false)
	log.SetOutput(io.Discard)
	if len(os.Args) == 2 && os.Args[1] == "--read-runtime-diagnostic" {
		report, e := readRuntimeDiagnostic()
		if e != nil {
			code := "RUNTIME_DIAGNOSTIC_UNAVAILABLE"
			if safe, ok := e.(diagnosticReadError); ok {
				code = string(safe)
			}
			json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": code})
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(report)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("FreeTurn Windows engine %s-preview; core v4.1.5; WireGuard Windows v1.1.1\n", engineVersion)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--preflight" {
		report := preflight()
		json.NewEncoder(os.Stdout).Encode(report)
		if !report["ok"].(bool) {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--inspect-profile" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxMessage+1))
		var report *effectiveSettings
		if err == nil {
			var p *profile
			p, err = parseProfile(string(data))
			if err == nil {
				report, err = describeEffective(string(data), p.Core)
			}
		}
		if err != nil {
			fmt.Println(`{"ok":false,"error":"PROFILE_UNSUPPORTED_OR_INVALID"}`)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "settings": report})
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-profile" {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, maxMessage+1))
		if e == nil {
			_, e = parseProfile(string(b))
		}
		if e != nil {
			fmt.Println(`{"ok":false,"error":"PROFILE_UNSUPPORTED_OR_INVALID"}`)
			os.Exit(1)
		}
		fmt.Println(`{"ok":true}`)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-bootstrap" {
		data, e := io.ReadAll(io.LimitReader(os.Stdin, maxMessage+1))
		if e != nil || checkManagedBootstrap(data) != nil {
			fmt.Println(`{"ok":false,"error":"MANAGED_BOOTSTRAP_INVALID"}`)
			os.Exit(1)
		}
		fmt.Println(`{"ok":true}`)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--build-managed" {
		data, e := io.ReadAll(io.LimitReader(os.Stdin, maxManagedMessage+1))
		var result *managedBuildResult
		if e == nil {
			result, e = buildManagedUpdate(data)
		}
		if e != nil {
			fmt.Println(`{"ok":false,"error":"MANAGED_CONFIG_INVALID"}`)
			os.Exit(1)
		}
		// Private child-process IPC, not a diagnostic/export command.
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}
	if len(os.Args) == 2 && (os.Args[1] == "--new-enrollment-key" || os.Args[1] == "--check-enrollment-key" || os.Args[1] == "--build-enrollment") {
		data, e := io.ReadAll(io.LimitReader(os.Stdin, maxManagedMessage+1))
		var result any
		if e == nil {
			if os.Args[1] == "--build-enrollment" {
				result, e = buildInitialManaged(data)
			} else {
				result, e = enrollmentKeyOperation(data, os.Args[1] == "--new-enrollment-key")
			}
		}
		if e != nil {
			fmt.Println(`{"ok":false,"error":"MANAGED_ENROLLMENT_INVALID"}`)
			os.Exit(1)
		}
		// Private child IPC; never include this output in diagnostics.
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-routing" {
		data, e := io.ReadAll(io.LimitReader(os.Stdin, maxMessage+1))
		var result map[string]any
		if e == nil {
			result, e = checkRouting(data)
		}
		if e != nil {
			fmt.Println(`{"ok":false,"error":"ROUTING_POLICY_INVALID"}`)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--check-system-routing" {
		data, e := io.ReadAll(io.LimitReader(os.Stdin, maxSystemMessage+1))
		var result map[string]any
		if e == nil {
			result, e = checkSystemRouting(data)
		}
		if e != nil {
			fmt.Println(`{"ok":false,"error":"SYSTEM_ROUTING_POLICY_INVALID"}`)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(result)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--network-state" {
		key, e := physicalNetworkFingerprint()
		json.NewEncoder(os.Stdout).Encode(map[string]any{"available": e == nil, "fingerprint": key})
		return
	}
	var err error
	if len(os.Args) == 3 && os.Args[1] == "--install" {
		err = install(os.Args[2])
	} else if len(os.Args) == 3 && os.Args[1] == "--setup" {
		err = setup(os.Args[2])
	} else if len(os.Args) == 2 && os.Args[1] == "--uninstall" {
		err = uninstall()
	} else if len(os.Args) == 2 && (os.Args[1] == "--broker" || os.Args[1] == "--tunnel") {
		var isService bool
		isService, err = svc.IsWindowsService()
		if err == nil && !isService {
			err = fmt.Errorf("SERVICE_CONTEXT_REQUIRED")
		}
		if err == nil {
			err = requireSystem()
		}
		var dir string
		if err == nil {
			dir, err = dataDir()
		}
		if err == nil {
			exe, _ := os.Executable()
			expected, _ := installDir()
			if filepath.Clean(exe) != filepath.Join(expected, "FreeTurn.Engine.exe") {
				err = fmt.Errorf("INSTALLED_PATH_REQUIRED")
			}
		}
		if err == nil {
			if os.Args[1] == "--broker" {
				err = svc.Run(brokerName, &broker{dir: dir})
			} else {
				err = runTunnel(dir)
			}
		}
	} else {
		fmt.Fprintln(os.Stderr, "FreeTurn Windows engine: no default action; use the desktop application.")
		os.Exit(2)
	}
	if err != nil {
		json.NewEncoder(os.Stderr).Encode(map[string]any{"ok": false, "error": "OPERATION_FAILED"})
		if len(os.Args) == 3 && os.Args[1] == "--setup" {
			switch err.Error() {
			case "STOP_BEFORE_UPGRADE":
				os.Exit(10)
			case "UPGRADE_OWNER_MISMATCH":
				os.Exit(11)
			case "UPGRADE_ROLLED_BACK":
				os.Exit(12)
			case "UPGRADE_ROLLBACK_FAILED":
				os.Exit(13)
			case "INCOMPLETE_INSTALLATION", "SERVICE_NAME_COLLISION":
				os.Exit(14)
			}
		}
		os.Exit(1)
	}
}
