package main

import "time"

// An active adapter or successful direct flow is not VPN success. Only the
// tunnel-service's WG handshake plus a fresh VPN-bound egress proof qualifies.
// Returns true when the new backend owns status (do not read a WGNT adapter).
func applySystemRoutingStatus(r *response, state runtimeState, running bool, now time.Time) bool {
	s := state.SystemRouting
	if s == nil || !s.Requested {
		return false
	}
	r.SystemRouting = s
	r.Handshake, r.Rx, r.Tx = s.Handshake, s.Rx, s.Tx
	if r.Captcha != "" {
		r.State = "captcha"
		r.Stage = "captcha"
		return true
	}
	if !s.Active || !running {
		r.State = "starting"
		r.Stage = "system_routing_start"
		if validSystemSetupStage(s.SetupStage) {
			r.Stage = s.SetupStage
		}
		return true
	}
	r.State = "tunnel_unverified"
	if state.State == "connected" {
		r.Stage = "handshake_wait"
		if s.Handshake {
			r.State = "handshake"
			r.Stage = "egress_check"
			age := now.Unix() - s.EgressAt
			if s.EgressAt > 0 && age >= 0 && age < 30 {
				r.State = "connected"
				r.Stage = "connected"
				r.DiagnosticError = ""
			}
		}
	}
	if systemRuntimeErrorCode(s.LastError) {
		r.DiagnosticError = s.LastError
	}
	return true
}
