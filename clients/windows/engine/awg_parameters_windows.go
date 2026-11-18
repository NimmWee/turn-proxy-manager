package main

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

var awgFields = []struct{ name, ipc string }{
	{"Jc", "jc"}, {"Jmin", "jmin"}, {"Jmax", "jmax"},
	{"S1", "s1"}, {"S2", "s2"}, {"S3", "s3"}, {"S4", "s4"},
	{"H1", "h1"}, {"H2", "h2"}, {"H3", "h3"}, {"H4", "h4"},
	{"I1", "i1"}, {"I2", "i2"}, {"I3", "i3"}, {"I4", "i4"}, {"I5", "i5"},
	{"HeaderProtectionKey", "header_protection_key"}, {"ContentPaddingAddition", "content_padding_addition"},
	{"RekeyAfterTime", "rekey_after_time"}, {"RekeyTimeout", "rekey_timeout"}, {"RejectAfterTime", "reject_after_time"},
	{"KeepaliveTimeout", "keepalive_timeout"}, {"MaxHandshakeAttempts", "max_handshake_attempts"},
	{"RandomTrailers", "random_trailers"}, {"DisableCookies", "disable_cookies"},
}

type awgRange struct{ lo, hi uint64 }

func awgNumber(raw string, max uint64) (uint64, bool) {
	n, e := strconv.ParseUint(raw, 10, 32)
	return n, e == nil && n <= max && strconv.FormatUint(n, 10) == raw
}
func awgRangeValue(raw string, min, max uint64, zero bool) (awgRange, string, bool) {
	parts := strings.Split(raw, "-")
	if len(parts) < 1 || len(parts) > 2 {
		return awgRange{}, "", false
	}
	lo, ok := awgNumber(parts[0], max)
	if !ok {
		return awgRange{}, "", false
	}
	hi := lo
	if len(parts) == 2 {
		hi, ok = awgNumber(parts[1], max)
		if !ok {
			return awgRange{}, "", false
		}
	}
	if hi < lo || lo < min && !(zero && lo == 0 && hi == 0) {
		return awgRange{}, "", false
	}
	canonical := strconv.FormatUint(lo, 10)
	if hi != lo {
		canonical += "-" + strconv.FormatUint(hi, 10)
	}
	return awgRange{lo, hi}, canonical, true
}

// Complete grammar, bounded output. The upstream parser otherwise ignores
// non-tag text and extra tag arguments; never silently accept those here.
func awgCPS(raw string) (string, bool) {
	if len(raw) > 4096 {
		return "", false
	}
	if raw == "" {
		return "", true
	}
	var canonical strings.Builder
	size, tags := uint64(0), 0
	for remaining := raw; remaining != ""; {
		if remaining[0] != '<' {
			return "", false
		}
		end := strings.IndexByte(remaining, '>')
		if end < 0 {
			return "", false
		}
		fields := strings.Fields(remaining[1:end])
		if len(fields) == 0 || len(fields) > 2 {
			return "", false
		}
		key := fields[0]
		value := ""
		if len(fields) == 2 {
			value = fields[1]
		}
		var length uint64
		switch key {
		case "b":
			value = strings.TrimPrefix(value, "0x")
			data, e := hex.DecodeString(value)
			if e != nil || len(data) == 0 || len(data) > 1280 {
				return "", false
			}
			length = uint64(len(data))
			value = "0x" + hex.EncodeToString(data)
		case "r", "rc", "rd":
			var ok bool
			length, ok = awgNumber(value, 1280)
			if !ok || length == 0 {
				return "", false
			}
		case "t":
			if len(fields) != 1 {
				return "", false
			}
			length = 4
		default:
			return "", false
		}
		size += length
		tags++
		if size > 1280 || tags > 12 {
			return "", false
		}
		canonical.WriteByte('<')
		canonical.WriteString(key)
		if key != "t" {
			canonical.WriteByte(' ')
			canonical.WriteString(value)
		}
		canonical.WriteByte('>')
		remaining = remaining[end+1:]
	}
	return canonical.String(), true
}

func awgParameters(raw string) (string, string, error) {
	known := map[string]bool{}
	for _, field := range awgFields {
		known[field.name] = true
	}
	values := map[string]string{}
	ranges := map[string]awgRange{}
	var base strings.Builder
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		text := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(text, "[") {
			section = text
		}
		key, value, ok := strings.Cut(text, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || !known[key] {
			base.WriteString(line)
			base.WriteByte('\n')
			continue
		}
		if section != "[Interface]" {
			return "", "", errMemoryWGConfig
		}
		if _, duplicate := values[key]; duplicate {
			return "", "", errMemoryWGConfig
		}
		canonical := ""
		valid := true
		switch key {
		case "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4":
			max := uint64(512)
			if key == "Jc" {
				max = 16
			} else if key == "Jmin" || key == "Jmax" {
				max = 1280
			} else if key == "S4" {
				max = 64
			}
			var n uint64
			n, valid = awgNumber(value, max)
			canonical = strconv.FormatUint(n, 10)
			ranges[key] = awgRange{n, n}
		case "H1", "H2", "H3", "H4":
			ranges[key], canonical, valid = awgRangeValue(value, 1, 1<<32-1, false)
		case "I1", "I2", "I3", "I4", "I5":
			canonical, valid = awgCPS(value)
		case "HeaderProtectionKey":
			data, e := base64.StdEncoding.Strict().DecodeString(value)
			valid = e == nil && len(data) == 32 && base64.StdEncoding.EncodeToString(data) == value && strings.Trim(string(data), "\x00") != ""
			canonical = hex.EncodeToString(data)
		case "ContentPaddingAddition":
			ranges[key], canonical, valid = awgRangeValue(value, 0, 64, true)
		case "RekeyAfterTime":
			ranges[key], canonical, valid = awgRangeValue(value, 30, 150, true)
		case "RejectAfterTime":
			ranges[key], canonical, valid = awgRangeValue(value, 60, 180, true)
		case "RekeyTimeout":
			ranges[key], canonical, valid = awgRangeValue(value, 3, 15, true)
		case "KeepaliveTimeout":
			ranges[key], canonical, valid = awgRangeValue(value, 3, 30, true)
		case "MaxHandshakeAttempts":
			ranges[key], canonical, valid = awgRangeValue(value, 1, 20, true)
		case "RandomTrailers", "DisableCookies":
			switch strings.ToLower(value) {
			case "true", "on", "yes", "1":
				canonical = "true"
			case "false", "off", "no", "0":
				canonical = "false"
			default:
				valid = false
			}
		}
		if !valid {
			return "", "", errMemoryWGConfig
		}
		values[key] = canonical
	}
	if ranges["Jmin"].hi > ranges["Jmax"].lo || ranges["Jc"].hi > 0 && (ranges["Jmin"].lo == 0 || ranges["Jmax"].lo == 0) {
		return "", "", errMemoryWGConfig
	}
	headers := []awgRange{{1, 1}, {2, 2}, {3, 3}, {4, 4}}
	for i, key := range []string{"H1", "H2", "H3", "H4"} {
		if _, ok := values[key]; ok {
			headers[i] = ranges[key]
		}
	}
	for i, left := range headers {
		for j := 0; j < i; j++ {
			right := headers[j]
			if left.lo <= right.hi && right.lo <= left.hi {
				return "", "", errMemoryWGConfig
			}
		}
	}
	if _, keyed := values["HeaderProtectionKey"]; keyed {
		for _, key := range []string{"S1", "S2", "S3", "S4"} {
			if ranges[key].lo < 12 {
				return "", "", errMemoryWGConfig
			}
		}
	}
	if ranges["S4"].hi+ranges["ContentPaddingAddition"].hi > 64 {
		return "", "", errMemoryWGConfig
	}
	effective := func(name string, fallback uint64) awgRange {
		r := ranges[name]
		if r.hi == 0 {
			return awgRange{fallback, fallback}
		}
		return r
	}
	reject := effective("RejectAfterTime", 180)
	rekey := effective("RekeyAfterTime", 120)
	keep := effective("KeepaliveTimeout", 10)
	retry := effective("RekeyTimeout", 5)
	if reject.lo <= rekey.hi || reject.lo <= keep.hi+retry.hi {
		return "", "", errMemoryWGConfig
	}
	var ipc strings.Builder
	for _, field := range awgFields {
		if value, ok := values[field.name]; ok {
			ipc.WriteString(field.ipc)
			ipc.WriteByte('=')
			ipc.WriteString(value)
			ipc.WriteByte('\n')
		}
	}
	return base.String(), ipc.String(), nil
}
