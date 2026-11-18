package main

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

type coreEvent struct {
	Seq     uint64 `json:"seq"`
	At      int64  `json:"at"`
	Level   string `json:"level"`
	Code    string `json:"code"`
	Stream  int    `json:"stream"`
	Streams int    `json:"streams,omitempty"`
	Total   int    `json:"total,omitempty"`
}

var streamMarker = regexp.MustCompile(`\[STREAM ([0-9]{1,2})\]`)

func validEventCode(code string) bool {
	switch code {
	case "VK_AUTH_START", "VK_JOIN_RETRY", "VK_PREVIEW_RETRY", "AUTH_CACHE", "CAPTCHA_AUTO_START", "CAPTCHA_MANUAL", "CAPTCHA_TOKEN", "CAPTCHA_RETRY", "DNS_UDP", "DNS_DOH", "DNS_QUERY_FAILED", "TURN_READY", "TURN_RETRY", "STREAMS_CHANGED", "SESSION_CONNECTING", "SESSION_READY", "SESSION_ERROR", "CORE_WARNING", "CORE_ERROR":
		return true
	}
	return code != "" && safeRuntimeError(code) == code
}
func coreEventCode(level, message string) string {
	m := strings.ToLower(message)
	switch {
	case strings.Contains(m, "turn allocation up:"):
		return "TURN_READY"
	case strings.Contains(m, "join page warm-up failed"):
		return "VK_JOIN_RETRY"
	case strings.Contains(m, "getcallpreview failed"):
		return "VK_PREVIEW_RETRY"
	case strings.Contains(m, "[vk auth]") || m == "provider=vk":
		return "VK_AUTH_START"
	case strings.Contains(m, "[captcha]") && strings.Contains(m, "got token"):
		return "CAPTCHA_TOKEN"
	case strings.Contains(m, "[captcha]") && strings.Contains(m, "manual"):
		return "CAPTCHA_MANUAL"
	case strings.Contains(m, "[captcha]") && (strings.Contains(m, "failed") || strings.Contains(m, "fallback")):
		return "CAPTCHA_RETRY"
	case strings.Contains(m, "[captcha]"):
		return "CAPTCHA_AUTO_START"
	case strings.Contains(m, "[dns]") && strings.Contains(m, "switching to doh"):
		return "DNS_DOH"
	case strings.Contains(m, "[dns]") && strings.Contains(m, "probe ok"):
		return "DNS_UDP"
	case strings.Contains(m, "[doh]"):
		return "DNS_QUERY_FAILED"
	case strings.Contains(m, "cached") && strings.Contains(m, "cred"):
		return "AUTH_CACHE"
	}
	_, code := coreLogDiagnostic(level, message)
	if code != "" {
		return code
	}
	if level == "warn" {
		return "CORE_WARNING"
	}
	if level == "error" {
		return "CORE_ERROR"
	}
	return ""
}

// Only fixed codes and bounded numbers are stored. No raw log string survives.
func (s *events) appendEventLocked(level, code string, stream, streams, total int) {
	if !validEventCode(code) {
		return
	}
	if level != "warn" && level != "error" {
		level = "info"
	}
	now := time.Now().UnixMilli()
	if n := len(s.state.Events); n > 0 {
		last := s.state.Events[n-1]
		if last.Code == code && last.Stream == stream && now-last.At < 1000 {
			return
		}
	}
	s.state.EventSequence++
	s.state.Events = append(s.state.Events, coreEvent{s.state.EventSequence, now, level, code, stream, streams, total})
	if len(s.state.Events) > 128 {
		copy(s.state.Events, s.state.Events[len(s.state.Events)-128:])
		s.state.Events = s.state.Events[:128]
	}
}
func logStream(message string) int {
	if match := streamMarker.FindStringSubmatch(message); len(match) == 2 {
		v, _ := strconv.Atoi(match[1])
		if v < 32 {
			return v
		}
	}
	return -1
}
func publicEvents(events []coreEvent) []coreEvent {
	result := make([]coreEvent, 0, min(len(events), 128))
	if len(events) > 128 {
		events = events[len(events)-128:]
	}
	for _, event := range events {
		if validEventCode(event.Code) && event.Seq > 0 && (event.Level == "info" || event.Level == "warn" || event.Level == "error") && event.Stream >= -1 && event.Stream < 32 && event.Streams >= 0 && event.Streams <= 256 && event.Total >= 0 && event.Total <= 256 {
			result = append(result, event)
		}
	}
	return result
}
