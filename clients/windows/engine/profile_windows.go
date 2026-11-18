package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/samosvalishe/free-turn-proxy/mobile"
	"golang.zx2c4.com/wireguard/windows/conf"
)

const maxMessage = 96 * 1024

var errProfile = errors.New("PROFILE_UNSUPPORTED_OR_INVALID")

type profile struct {
	Core, WG, Peer, Kind, Listen string
	AWG                          bool
}
type shareProfile struct {
	V         int             `json:"v"`
	Provider  string          `json:"provider"`
	Peer      string          `json:"peer"`
	Transport string          `json:"transport"`
	Mode      string          `json:"mode"`
	Bond      bool            `json:"bond"`
	Obf       string          `json:"obf"`
	Key       string          `json:"key"`
	Timing    int             `json:"timing"`
	N         int             `json:"n"`
	SPC       int             `json:"spc"`
	CID       string          `json:"cid"`
	Listen    string          `json:"listen"`
	DNS       string          `json:"dns"`
	DNSS      string          `json:"dnss"`
	MCap      bool            `json:"mcap"`
	KCP       json.RawMessage `json:"kcp"`
	Name      string          `json:"name"`
	VK        string          `json:"vk"`
	WG        string          `json:"wg"`
}

// Parse errors are intentionally fixed codes: upstream WG errors may contain keys.
func parseProfile(input string) (*profile, error) {
	if len(input) > maxMessage {
		return nil, errProfile
	}
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "freeturn://") {
		return nil, errProfile
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(input, "freeturn://"))
	if err != nil || len(raw) > 64*1024 || !uniqueJSON(raw) {
		return nil, errProfile
	}
	var s shareProfile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || s.V != 1 || (s.Provider != "vk" && s.Provider != "direct") {
		return nil, errProfile
	}
	if s.Mode == "" {
		s.Mode = "udp"
	}
	if s.Listen == "" {
		s.Listen = "127.0.0.1:9000"
	}
	if s.Mode != "udp" && s.Mode != "tcp" || s.Transport != "" && s.Transport != "tcp" && s.Transport != "udp" || s.Mode != "tcp" && (s.Bond || len(s.KCP) != 0) {
		return nil, errProfile
	}
	listenHost, listenPort, listenErr := net.SplitHostPort(s.Listen)
	lp, lpe := strconv.Atoi(listenPort)
	if listenErr != nil || lpe != nil || listenHost != "127.0.0.1" || lp < 1024 || lp > 65535 || lp == 8765 || s.WG != "" && (s.Listen != "127.0.0.1:9000" || s.Mode != "udp") {
		return nil, errProfile
	}
	if s.Obf == "" {
		s.Obf = "none"
	}
	if s.Obf != "none" && s.Obf != "rtpopus" && s.Obf != "rtpopus2" && s.Obf != "rtpopus3" || s.Obf != "none" && !hexSize(s.Key, 32) || !hexSize(s.CID, 16) {
		return nil, errProfile
	}
	host, port, err := net.SplitHostPort(s.Peer)
	address, ipErr := netip.ParseAddr(host)
	portNum, portErr := strconv.Atoi(port)
	if err != nil || ipErr != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || portErr != nil || portNum < 1 || portNum > 65535 {
		return nil, errProfile
	}
	u, err := url.Parse(s.VK)
	if (s.Provider == "vk" || s.VK != "") && (err != nil || u.Scheme != "https" || u.Host != "vk.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/call/join/") || len(strings.TrimPrefix(u.Path, "/call/join/")) == 0) {
		return nil, errProfile
	}
	if u != nil && strings.ContainsAny(strings.TrimPrefix(u.Path, "/call/join/"), "/\\%") {
		return nil, errProfile
	}
	if s.N == 0 {
		s.N = 6
		if s.Provider == "direct" {
			s.N = 1
		}
	}
	if s.SPC == 0 {
		s.SPC = 3
	}
	if s.N < 1 || s.N > 32 || s.SPC < 1 || s.SPC > 16 || s.Timing < 0 || s.Timing > 1000 {
		return nil, errProfile
	}
	if s.WG != "" && !safeWG(s.WG) {
		return nil, errProfile
	}
	config := map[string]any{}
	if json.Unmarshal([]byte(mobile.DefaultConfigJSON()), &config) != nil {
		return nil, errProfile
	}
	config["peer"], config["clientId"], config["provider"], config["subUrl"], config["routes"] = s.Peer, s.CID, s.Provider, "", false
	config["turn"].(map[string]any)["n"] = s.N
	if s.Transport == "" {
		s.Transport = "tcp"
	}
	config["turn"].(map[string]any)["transport"] = s.Transport
	config["proxy"] = map[string]any{"mode": s.Mode, "listen": s.Listen, "bond": s.Bond}
	if len(s.KCP) != 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(s.KCP, &fields) != nil || fields == nil {
			return nil, errProfile
		}
		names := map[string]string{"nodelay": "noDelay", "interval": "interval", "resend": "resend", "nc": "nc", "sndwnd": "sndWnd", "rcvwnd": "rcvWnd", "mtu": "mtu", "acknodelay": "ackNoDelay"}
		defaults, ok := config["kcp"].(map[string]any)
		if !ok {
			return nil, errProfile
		}
		for name, raw := range fields {
			target, ok := names[name]
			if !ok {
				return nil, errProfile
			}
			var value any
			if json.Unmarshal(raw, &value) != nil {
				return nil, errProfile
			}
			defaults[target] = value
		}
	}
	links := []string{}
	if s.Provider == "vk" {
		links = append(links, s.VK)
	}
	config["vk"] = map[string]any{"links": links, "streamsPerCred": s.SPC, "manualCaptcha": s.MCap && s.Provider == "vk", "autoCaptcha": true, "advancedCaptcha": false, "platform": "desktop"}
	key := s.Key
	if s.Obf == "none" {
		key = ""
	}
	config["obf"] = map[string]any{"profile": s.Obf, "key": key, "timingMs": s.Timing}
	if s.DNS == "" {
		s.DNS = "auto"
	}
	servers := []string{}
	if s.DNSS != "" {
		servers = strings.Split(s.DNSS, ",")
	}
	config["dns"] = map[string]any{"mode": s.DNS, "servers": servers}
	config["log"] = map[string]any{"debug": false}
	config["tunnel"] = map[string]any{"mode": "none", "config": "", "mtu": 1280}
	b, err := json.Marshal(config)
	if err != nil || mobile.ValidateConfig(string(b)) != "" {
		return nil, errProfile
	}
	kind := "wireguard"
	if s.WG == "" {
		kind = s.Mode + "-forwarder"
	}
	return &profile{Core: string(b), WG: s.WG, Peer: s.Peer, Kind: kind, Listen: s.Listen, AWG: isAWG(s.WG)}, nil
}

func hexSize(s string, n int) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == n }

func safeWG(text string) bool {
	if len(text) > 16*1024 || strings.ContainsRune(text, '\x00') {
		return false
	}
	section := ""
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[Interface]" && line != "[Peer]" || seen[line] {
				return false
			}
			seen[line] = true
			section = line
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return false
		}
		key := strings.TrimSpace(parts[0])
		allowed := "|PrivateKey|Address|DNS|MTU|"
		for _, field := range awgFields {
			allowed += field.name + "|"
		}
		if section == "[Peer]" {
			allowed = "|PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive|"
		}
		if section == "" || !strings.Contains(allowed, "|"+key+"|") || seen[section+key] {
			return false
		}
		seen[section+key] = true
	}
	c, _, err := memoryWGConfig(text)
	if err != nil || len(c.Peers) != 1 || len(c.Interface.Addresses) == 0 || len(c.Interface.DNS) == 0 || len(c.Interface.DNSSearch) != 0 || c.Interface.MTU < 1280 || c.Interface.MTU > 1420 {
		return false
	}
	zero := conf.Key{}
	p := c.Peers[0]
	if c.Interface.PrivateKey == zero || p.PublicKey == zero || p.PresharedKey == zero || p.Endpoint.Host != "127.0.0.1" || p.Endpoint.Port != 9000 {
		return false
	}
	if len(p.AllowedIPs) != 2 {
		return false
	}
	a := map[string]bool{}
	for _, ip := range p.AllowedIPs {
		a[ip.String()] = true
	}
	if !a["0.0.0.0/0"] || !a["::/0"] {
		return false
	}
	hasIPv4 := false
	for _, ip := range c.Interface.Addresses {
		if !ip.Addr().IsPrivate() || ip.Bits() != ip.Addr().BitLen() {
			return false
		}
		if ip.Addr().Is4() {
			hasIPv4 = true
		}
	}
	return hasIPv4
}

// Token walk rejects duplicate keys (including nested keys), excessive nesting,
// trailing JSON values, and control characters in names before typed decoding.
func uniqueJSON(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 8 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return false
				}
				key, ok := k.(string)
				canonical := strings.ToLower(key)
				if !ok || keys[canonical] || strings.IndexFunc(key, unicode.IsControl) >= 0 {
					return false
				}
				keys[canonical] = true
				if !walk(depth + 1) {
					return false
				}
			}
		case '[':
			for d.More() {
				if !walk(depth + 1) {
					return false
				}
			}
		default:
			return false
		}
		_, e = d.Token()
		return e == nil
	}
	if !walk(0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
