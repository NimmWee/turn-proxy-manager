package main

import (
	"errors"
	"golang.zx2c4.com/wireguard/windows/conf"
	"strings"
)

var errMemoryWGConfig = errors.New("WG_MEMORY_CONFIG_INVALID")

// Never pass the stripped base config to WireGuardNT: AWG requires the
// explicitly selected userspace backend. Diagnostics must not expose UAPI.
func memoryWGConfig(raw string) (*conf.Config, string, error) {
	if len(raw) > 16*1024 || strings.ContainsRune(raw, '\x00') {
		return nil, "", errMemoryWGConfig
	}
	base, extensions, e := awgParameters(raw)
	if e != nil {
		return nil, "", errMemoryWGConfig
	}
	config, e := conf.FromWgQuick(base, "FTM")
	if e != nil {
		return nil, "", errMemoryWGConfig
	}
	return config, extensions, nil
}
func awgProtocol(raw string) string {
	_, extensions, e := memoryWGConfig(raw)
	if e != nil || extensions == "" {
		return ""
	}
	protocol := "amneziawg1"
	for _, line := range strings.Split(extensions, "\n") {
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies":
			return "amneziawg3"
		case "s3", "s4", "i1", "i2", "i3", "i4", "i5":
			protocol = "amneziawg2"
		case "h1", "h2", "h3", "h4":
			if strings.Contains(value, "-") {
				protocol = "amneziawg2"
			}
		}
	}
	return protocol
}
func isAWG(raw string) bool { return awgProtocol(raw) != "" }
