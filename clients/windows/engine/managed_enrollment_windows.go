package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/windows/conf"
)

type enrollmentKey struct {
	Ok         bool   `json:"ok"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func enrollmentOrigin(origin string) (netip.Addr, bool) {
	ip, e := netip.ParseAddr(strings.TrimPrefix(origin, "https://"))
	return ip, e == nil && publicIPv4(ip) && origin == "https://"+ip.String()
}
func validEnrollmentKey(privateKey, publicKey, origin string) bool {
	_, ok := enrollmentOrigin(origin)
	if !ok || !managedKey(privateKey) || !managedKey(publicKey) {
		return false
	}
	key, e := conf.NewPrivateKeyFromString(privateKey)
	return e == nil && !key.IsZero() && key.Public().String() == publicKey
}
func newEnrollmentKey(origin string) (*enrollmentKey, error) {
	if _, ok := enrollmentOrigin(origin); !ok {
		return nil, errors.New("MANAGED_ENROLLMENT_INVALID")
	}
	key, e := conf.NewPrivateKey()
	if e != nil {
		return nil, errors.New("MANAGED_ENROLLMENT_INVALID")
	}
	return &enrollmentKey{Ok: true, PrivateKey: key.String(), PublicKey: key.Public().String()}, nil
}
func enrollmentKeyOperation(raw []byte, generate bool) (any, error) {
	invalid := errors.New("MANAGED_ENROLLMENT_INVALID")
	if len(raw) > 4096 || !uniqueJSON(raw) {
		return nil, invalid
	}
	fields := "origin private_key public_key"
	if generate {
		fields = "origin"
	}
	if _, ok := managedObject(raw, fields); !ok {
		return nil, invalid
	}
	var v struct {
		Origin     string `json:"origin"`
		PrivateKey string `json:"private_key"`
		PublicKey  string `json:"public_key"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return nil, invalid
	}
	if generate {
		return newEnrollmentKey(v.Origin)
	}
	if !validEnrollmentKey(v.PrivateKey, v.PublicKey, v.Origin) {
		return nil, invalid
	}
	return map[string]bool{"ok": true}, nil
}
func buildInitialManaged(raw []byte) (*managedBuildResult, error) {
	invalid := errors.New("MANAGED_CONFIG_INVALID")
	if len(raw) > maxManagedMessage || !uniqueJSON(raw) {
		return nil, invalid
	}
	if _, ok := managedObject(raw, "manifest private_key public_key origin device_id client_id etag min_revision"); !ok {
		return nil, invalid
	}
	var v struct {
		Manifest    json.RawMessage `json:"manifest"`
		PrivateKey  string          `json:"private_key"`
		PublicKey   string          `json:"public_key"`
		Origin      string          `json:"origin"`
		DeviceID    string          `json:"device_id"`
		ClientID    string          `json:"client_id"`
		ETag        string          `json:"etag"`
		MinRevision int64           `json:"min_revision"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF || v.MinRevision < 1 || !validEnrollmentKey(v.PrivateKey, v.PublicKey, v.Origin) || !hexSize(v.ClientID, 16) || strings.ToLower(v.ClientID) != v.ClientID {
		return nil, invalid
	}
	private, _ := conf.NewPrivateKeyFromString(v.PrivateKey)
	ip, _ := enrollmentOrigin(v.Origin)
	return buildManagedWithKey(managedBuildRequest{Manifest: v.Manifest, PublicKey: v.PublicKey, Origin: v.Origin, DeviceID: v.DeviceID, ETag: v.ETag, MinRevision: v.MinRevision}, *private, ip, v.ClientID)
}
