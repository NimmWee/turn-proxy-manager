package main

import (
	"encoding/json"
	"errors"
	"path/filepath"
)

type diagnosticReadError string

func (e diagnosticReadError) Error() string { return string(e) }

// Explicit SYSTEM read-only diagnostic. Never read/export profile or keys.
func readRuntimeDiagnostic() (map[string]any, error) {
	if requireSystem() != nil {
		return nil, diagnosticReadError("SYSTEM_REQUIRED")
	}
	dir, e := dataDir()
	if e != nil {
		return nil, e
	}
	data, e := readSecret(filepath.Join(dir, "runtime.dpapi"), "FreeTurn runtime v1")
	if e != nil {
		return nil, diagnosticReadError("RUNTIME_UNREADABLE")
	}
	var snapshot runtimeState
	if json.Unmarshal(data, &snapshot) != nil {
		return nil, errors.New("RUNTIME_INVALID")
	}
	status := "unknown"
	switch snapshot.State {
	case "idle", "connecting", "connected", "error", "captcha":
		status = snapshot.State
	}
	code := ""
	if snapshot.ErrorCode != "" {
		code = safeRuntimeError(snapshot.ErrorCode)
	}
	stage := "unknown"
	switch snapshot.Stage {
	case "transport_start", "vk_auth", "captcha", "turn_connect", "relay_ready", "error":
		stage = snapshot.Stage
	}
	return map[string]any{"ok": true, "readOnly": true, "state": status, "stage": stage, "streams": snapshot.Streams, "total": snapshot.TotalStreams, "hasCaptcha": snapshot.Captcha != "", "errorCode": code, "started": snapshot.Started, "updated": snapshot.Updated}, nil
}
