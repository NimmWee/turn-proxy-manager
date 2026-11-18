package main

import (
	"strings"
	"time"
)

type failureReport struct {
	AttemptID uint64
	Code      string
	At        int64
	Stage     string
}

func (s *events) stageLocked(stage string) {
	if s.state.Stage != stage {
		s.state.Stage = stage
		s.state.StageSince = time.Now().Unix()
		s.state.LastProgress = s.state.StageSince
	}
}

// Never retain, return or log the input. Only fixed codes cross the IPC boundary.
func coreLogDiagnostic(level, message string) (stage, code string) {
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "[captcha]"):
		stage = "captcha"
	case strings.Contains(m, "[vk auth]") || m == "provider=vk":
		stage = "vk_auth"
	case strings.Contains(m, "turn allocate") || strings.Contains(m, "dial turn") || strings.Contains(m, "resolve turn"):
		stage = "turn_connect"
	case strings.Contains(m, "turn allocation up:"):
		stage = "relay_ready"
	}
	if level != "warn" && level != "error" {
		return stage, ""
	}
	switch {
	case strings.Contains(m, "terminal link error"):
		code = "VK_LINK_INVALID"
	case strings.Contains(m, "rate limit") || strings.Contains(m, "lockout"):
		code = "VK_RATE_LIMIT"
	case strings.Contains(m, "captcha") && (strings.Contains(m, "timed out") || strings.Contains(m, "timeout")):
		code = "CAPTCHA_TIMEOUT"
	case strings.Contains(m, "no such host") || strings.Contains(m, "resolve turn"):
		code = "DNS_FAILED"
	case strings.Contains(m, "turn allocate"):
		code = "TURN_ALLOCATION_FAILED"
	case strings.Contains(m, "dial turn"):
		code = "TURN_CONNECT_FAILED"
	case strings.Contains(m, "all vk credentials failed") || strings.Contains(m, "auth error"):
		code = "VK_AUTH_FAILED"
	case strings.Contains(m, "deadline exceeded") || strings.Contains(m, "timed out") || strings.Contains(m, "timeout"):
		code = "NETWORK_TIMEOUT"
	case strings.Contains(m, "connection refused"):
		code = "NETWORK_REFUSED"
	case level == "error":
		code = "TRANSPORT_ERROR"
	}
	return
}

func safeRuntimeError(code string) string {
	if systemRuntimeErrorCode(code) {
		return code
	}
	switch code {
	case "PATH_STATE_INVALID", "AUTO_PATH_PROFILE_INVALID", "PROFILE_MISSING", "CONFIG_MISMATCH", "TRANSPORT_START_FAILED", "OTHER_VPN_OR_NONPHYSICAL_UPLINK", "NO_IPV4_PHYSICAL_UPLINK", "DNS_FAILED", "VK_LINK_INVALID", "VK_RATE_LIMIT", "VK_AUTH_FAILED", "CAPTCHA_TIMEOUT", "TURN_ALLOCATION_FAILED", "TURN_CONNECT_FAILED", "NETWORK_TIMEOUT", "NETWORK_REFUSED", "TRANSPORT_ERROR", "TUNNEL_START_FAILED":
		return code
	default:
		return "TUNNEL_START_FAILED"
	}
}
