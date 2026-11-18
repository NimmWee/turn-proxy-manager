package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.zx2c4.com/wireguard/windows/conf"
)

const maxManagedMessage = 256 * 1024

type managedBuildRequest struct {
	Manifest     json.RawMessage `json:"manifest"`
	CurrentShare string          `json:"current_share"`
	DeviceID     string          `json:"device_id"`
	PublicKey    string          `json:"public_key"`
	Origin       string          `json:"origin"`
	ETag         string          `json:"etag"`
	MinRevision  int64           `json:"min_revision"`
}
type managedManifest struct {
	SchemaVersion int    `json:"schema_version"`
	Format        string `json:"format"`
	DeviceID      string `json:"device_id"`
	Revision      int64  `json:"revision"`
	Name          string `json:"name"`
	Platform      string `json:"platform"`
	WireGuard     struct {
		ClientPublicKey     string   `json:"client_public_key"`
		Addresses           []string `json:"addresses"`
		ServerPublicKey     string   `json:"server_public_key"`
		PresharedKey        string   `json:"preshared_key"`
		AllowedIPs          []string `json:"allowed_ips"`
		DNS                 []string `json:"dns"`
		MTU                 int      `json:"mtu"`
		LocalEndpoint       string   `json:"local_endpoint"`
		PersistentKeepalive int      `json:"persistent_keepalive"`
		IPv6Policy          string   `json:"ipv6_policy"`
	} `json:"wireguard"`
	FreeTurn   shareProfile `json:"freeturn"`
	Management struct {
		Origin         string `json:"origin"`
		APIPath        string `json:"api_path"`
		InternalAPIIP  string `json:"internal_api_ip"`
		TLSServerName  string `json:"tls_server_name"`
		RefreshSeconds int    `json:"refresh_seconds"`
	} `json:"management"`
}
type managedBuildResult struct {
	Ok       bool   `json:"ok"`
	Share    string `json:"share"`
	ETag     string `json:"etag"`
	Revision int64  `json:"revision"`
}

func managedObject(raw []byte, fields string) (map[string]json.RawMessage, bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return nil, false
	}
	keys := strings.Fields(fields)
	if len(object) != len(keys) {
		return nil, false
	}
	for _, k := range keys {
		if _, ok := object[k]; !ok {
			return nil, false
		}
	}
	return object, true
}
func managedKey(key string) bool {
	raw, e := base64.StdEncoding.Strict().DecodeString(key)
	return e == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == key
}

// Private stdin/stdout contract. It reuses the locally owned private key and
// performs no persistence, service, DNS, routing or network operations.
func buildManagedUpdate(raw []byte) (*managedBuildResult, error) {
	invalid := errors.New("MANAGED_CONFIG_INVALID")
	if len(raw) > maxManagedMessage || !uniqueJSON(raw) {
		return nil, invalid
	}
	if _, ok := managedObject(raw, "manifest current_share device_id public_key origin etag min_revision"); !ok {
		return nil, invalid
	}
	var request managedBuildRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.MinRevision < 0 || len(request.Manifest) > 65536 {
		return nil, invalid
	}
	current, e := parseProfile(request.CurrentShare)
	if e != nil || current.Kind != "wireguard" || current.AWG {
		return nil, invalid
	}
	oldWG, e := conf.FromWgQuick(current.WG, "FTM")
	if e != nil {
		return nil, invalid
	}
	host, _, e := net.SplitHostPort(current.Peer)
	originIP, ipErr := netip.ParseAddr(host)
	if e != nil || ipErr != nil {
		return nil, invalid
	}
	return buildManagedWithKey(request, oldWG.Interface.PrivateKey, originIP, "")
}

func buildManagedWithKey(request managedBuildRequest, privateKey conf.Key, originIP netip.Addr, clientID string) (*managedBuildResult, error) {
	invalid := errors.New("MANAGED_CONFIG_INVALID")
	if len(request.Manifest) > 65536 || !uniqueJSON(request.Manifest) || !publicIPv4(originIP) || request.Origin != "https://"+originIP.String() || !managedKey(request.PublicKey) || privateKey.IsZero() || privateKey.Public().String() != request.PublicKey {
		return nil, invalid
	}
	object, ok := managedObject(request.Manifest, "schema_version format device_id revision name platform wireguard freeturn management")
	if !ok {
		return nil, invalid
	}
	if _, ok := managedObject(object["wireguard"], "client_public_key addresses server_public_key preshared_key allowed_ips dns mtu local_endpoint persistent_keepalive ipv6_policy"); !ok {
		return nil, invalid
	}
	ftObject, ok := managedObject(object["freeturn"], "v provider peer transport mode obf key n spc cid dns mcap vk")
	if !ok {
		return nil, invalid
	}
	if _, ok := managedObject(object["management"], "origin api_path internal_api_ip tls_server_name refresh_seconds"); !ok {
		return nil, invalid
	}
	if string(ftObject["mcap"]) != "true" && string(ftObject["mcap"]) != "false" {
		return nil, invalid
	}
	var m managedManifest
	if json.Unmarshal(request.Manifest, &m) != nil || m.SchemaVersion != 1 || m.Format != "ftm-managed" || !managedUUID.MatchString(m.DeviceID) || m.DeviceID == "00000000-0000-0000-0000-000000000000" || m.DeviceID != request.DeviceID || m.Revision < 1 || m.Revision < request.MinRevision || m.Platform != "windows" && m.Platform != "other" || utf8.RuneCountInString(m.Name) < 1 || utf8.RuneCountInString(m.Name) > 128 {
		return nil, invalid
	}
	for _, r := range m.Name {
		if unicode.IsControl(r) {
			return nil, invalid
		}
	}
	wg, ft, mg := m.WireGuard, m.FreeTurn, m.Management
	if wg.ClientPublicKey != request.PublicKey || !managedKey(wg.ServerPublicKey) || !managedKey(wg.PresharedKey) || len(wg.AllowedIPs) != 2 || wg.AllowedIPs[0] != "0.0.0.0/0" || wg.AllowedIPs[1] != "::/0" || wg.LocalEndpoint != "127.0.0.1:9000" || wg.IPv6Policy != "block" || wg.MTU < 1280 || wg.MTU > 1420 || wg.PersistentKeepalive < 1 || wg.PersistentKeepalive > 120 || len(wg.Addresses) != 1 || len(wg.DNS) < 1 || len(wg.DNS) > 4 {
		return nil, invalid
	}
	address, e := netip.ParsePrefix(wg.Addresses[0])
	subnet := netip.MustParsePrefix("10.77.43.0/24")
	if e != nil || !address.Addr().Is4() || address.Bits() != 32 || address.String() != wg.Addresses[0] || !subnet.Contains(address.Addr()) || address.Addr().As4()[3] < 2 || address.Addr().As4()[3] == 255 {
		return nil, invalid
	}
	for _, s := range wg.DNS {
		ip, e := netip.ParseAddr(s)
		if e != nil || !publicIPv4(ip) || ip.String() != s {
			return nil, invalid
		}
	}
	if mg.Origin != request.Origin || mg.APIPath != "/api/client/v1/" || mg.InternalAPIIP != "10.77.43.1" || mg.TLSServerName != originIP.String() || mg.RefreshSeconds != 1800 {
		return nil, invalid
	}
	ftHost, _, e := net.SplitHostPort(ft.Peer)
	if e != nil || ftHost != originIP.String() || ft.V != 1 || ft.Provider != "vk" || ft.Transport != "tcp" || ft.Mode != "udp" || ft.Obf != "rtpopus3" || !hexSize(ft.Key, 32) || strings.ToLower(ft.Key) != ft.Key || !hexSize(ft.CID, 16) || strings.ToLower(ft.CID) != ft.CID || ft.N < 1 || ft.N > 32 || ft.SPC < 1 || ft.SPC > 16 || ft.DNS != "auto" && ft.DNS != "plain" && ft.DNS != "doh" {
		return nil, invalid
	}
	if clientID != "" && ft.CID != clientID {
		return nil, invalid
	}
	canonical, e := canonicalManagedJSON(request.Manifest)
	if e != nil {
		return nil, invalid
	}
	digest := sha256.Sum256(canonical)
	etag := "\"" + hex.EncodeToString(digest[:]) + "\""
	if request.ETag != etag {
		return nil, invalid
	}
	wgText := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 127.0.0.1:9000\nPersistentKeepalive = %d\n", privateKey.String(), wg.Addresses[0], strings.Join(wg.DNS, ", "), wg.MTU, wg.ServerPublicKey, wg.PresharedKey, wg.PersistentKeepalive)
	ftObject["name"], _ = json.Marshal(m.Name)
	ftObject["wg"], _ = json.Marshal(wgText)
	native, e := json.Marshal(ftObject)
	if e != nil {
		return nil, invalid
	}
	share := "freeturn://" + base64.RawURLEncoding.EncodeToString(native)
	if len(share) > 65536 {
		return nil, invalid
	}
	if _, e := parseProfile(share); e != nil {
		return nil, invalid
	}
	return &managedBuildResult{Ok: true, Share: share, ETag: etag, Revision: m.Revision}, nil
}
