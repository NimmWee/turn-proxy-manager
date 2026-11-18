package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
)

type managedBootstrap struct {
	Version       int    `json:"version"`
	Format        string `json:"format"`
	DeviceID      string `json:"device_id"`
	PublicKey     string `json:"public_key"`
	Origin        string `json:"origin"`
	InternalAPIIP string `json:"internal_api_ip"`
	ClaimNonce    string `json:"claim_nonce"`
	ExpiresAt     string `json:"expires_at"`
	Share         string `json:"share"`
}

var managedUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var managedNonce = regexp.MustCompile(`^ftmb1_[A-Za-z0-9_-]{43}$`)

// Pure validation: no token issuance, storage, service, DNS or network calls.
// No private values (including key/parser errors) escape this boundary.
func checkManagedBootstrap(raw []byte) error {
	invalid := errors.New("MANAGED_BOOTSTRAP_INVALID")
	if len(raw) > maxMessage || !uniqueJSON(raw) {
		return invalid
	}
	var b managedBootstrap
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil || d.Decode(new(any)) != io.EOF || b.Version != 1 || b.Format != "ftm-bootstrap" || !managedUUID.MatchString(b.DeviceID) || b.DeviceID == "00000000-0000-0000-0000-000000000000" || !managedNonce.MatchString(b.ClaimNonce) || b.InternalAPIIP != "10.77.43.1" || len(b.Share) > 65536 {
		return invalid
	}
	if _, e := time.Parse(time.RFC3339, b.ExpiresAt); e != nil {
		return invalid
	}
	// Current server envelope intentionally allows only canonical HTTPS IPv4.
	// Domain/custom internal addressing needs a separate future contract version.
	p, e := parseProfile(b.Share)
	if e != nil || p.Kind != "wireguard" || p.AWG {
		return invalid
	}
	host, _, e := net.SplitHostPort(p.Peer)
	ip, ipErr := netip.ParseAddr(host)
	if e != nil || ipErr != nil || !publicIPv4(ip) || b.Origin != "https://"+ip.String() {
		return invalid
	}
	config, e := conf.FromWgQuick(p.WG, "FTM")
	if e != nil {
		return invalid
	}
	key, e := base64.StdEncoding.Strict().DecodeString(b.PublicKey)
	if e != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != b.PublicKey || config.Interface.PrivateKey.Public().String() != b.PublicKey {
		return invalid
	}
	var share shareProfile
	decoded, _ := base64.RawURLEncoding.Strict().DecodeString(b.Share[len("freeturn://"):])
	if json.Unmarshal(decoded, &share) != nil || share.Provider != "vk" || share.Obf != "rtpopus3" || share.Transport != "tcp" || share.Mode != "udp" {
		return invalid
	}
	return nil
}
