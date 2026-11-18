// Package updatecheck verifies signed release metadata and installer bytes.
// It also supports transport to a temporary file for a future update workflow.
package updatecheck

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const signatureContext = "FreeTurn.Windows.Release.v1\x00"
const MaxEnvelope = 24 * 1024
const MaxArtifact = 256 << 20

var (
	ErrTrust     = errors.New("UPDATE_TRUST_REQUIRED")
	ErrMetadata  = errors.New("UPDATE_METADATA_INVALID")
	ErrSignature = errors.New("UPDATE_SIGNATURE_INVALID")
	ErrExpired   = errors.New("UPDATE_EXPIRED_OR_FUTURE")
	ErrRollback  = errors.New("UPDATE_ROLLBACK_REFUSED")
	ErrVersion   = errors.New("UPDATE_NOT_NEWER")
	ErrArtifact  = errors.New("UPDATE_PACKAGE_MISMATCH")
)

type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Artifact struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema    int      `json:"schema"`
	App       string   `json:"app"`
	Platform  string   `json:"platform"`
	Channel   string   `json:"channel"`
	Version   string   `json:"version"`
	Sequence  uint64   `json:"sequence"`
	IssuedAt  string   `json:"issuedAt"`
	ExpiresAt string   `json:"expiresAt"`
	Artifact  Artifact `json:"artifact"`
}
type Trust struct {
	PublicKey ed25519.PublicKey
	Origin    string
	Channel   string
}

// StrictJSON accepts insignificant envelope/config whitespace, but rejects
// duplicate/unknown/case-aliased keys, alternate ordering and trailing values.
func StrictJSON(raw []byte, value any) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	canonical, e := json.Marshal(value)
	if e != nil {
		return false
	}
	var compact bytes.Buffer
	return json.Compact(&compact, raw) == nil && bytes.Equal(canonical, compact.Bytes())
}

func validOrigin(origin string) bool {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" || u.Host != u.Hostname() || u.String() != origin {
		return false
	}
	host := u.Hostname()
	if host != strings.ToLower(host) || len(host) > 253 {
		return false
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func version(raw string) (parts [3]uint64, ok bool) {
	values := strings.Split(raw, ".")
	if len(values) != 3 {
		return parts, false
	}
	for i, value := range values {
		n, e := strconv.ParseUint(value, 10, 16)
		if e != nil || strconv.FormatUint(n, 10) != value {
			return parts, false
		}
		parts[i] = n
	}
	return parts, true
}
func newer(candidate, current [3]uint64) bool {
	for i := range candidate {
		if candidate[i] != current[i] {
			return candidate[i] > current[i]
		}
	}
	return false
}
func lowerSHA(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	for _, c := range raw {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validTrust(trust Trust) bool {
	return len(trust.PublicKey) == ed25519.PublicKeySize && !bytes.Equal(trust.PublicKey, make([]byte, ed25519.PublicKeySize)) &&
		validOrigin(trust.Origin) && (trust.Channel == "preview" || trust.Channel == "stable")
}

func Verify(raw []byte, trust Trust, currentVersion string, acceptedSequence uint64, now time.Time) (*Manifest, error) {
	if !validTrust(trust) {
		return nil, ErrTrust
	}
	if len(raw) > MaxEnvelope {
		return nil, ErrMetadata
	}
	var envelope Envelope
	if !StrictJSON(raw, &envelope) {
		return nil, ErrMetadata
	}
	payload, e := base64.RawURLEncoding.Strict().DecodeString(envelope.Payload)
	if e != nil || len(payload) > 8192 || base64.RawURLEncoding.EncodeToString(payload) != envelope.Payload {
		return nil, ErrMetadata
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(envelope.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(sig) != envelope.Signature {
		return nil, ErrSignature
	}
	if !ed25519.Verify(trust.PublicKey, append([]byte(signatureContext), payload...), sig) {
		return nil, ErrSignature
	}
	var manifest Manifest
	if !StrictJSON(payload, &manifest) {
		return nil, ErrMetadata
	}
	canonical, _ := json.Marshal(manifest)
	if !bytes.Equal(canonical, payload) {
		return nil, ErrMetadata
	}
	if manifest.Schema != 1 || manifest.App != "freeturn-windows" || manifest.Platform != "windows-amd64" || manifest.Channel != trust.Channel {
		return nil, ErrMetadata
	}
	candidate, candidateOK := version(manifest.Version)
	current, currentOK := version(currentVersion)
	if !candidateOK || !currentOK {
		return nil, ErrMetadata
	}
	if !newer(candidate, current) {
		return nil, ErrVersion
	}
	if manifest.Sequence == 0 || manifest.Sequence > math.MaxInt64 || acceptedSequence > math.MaxInt64 || manifest.Sequence <= acceptedSequence {
		return nil, ErrRollback
	}
	issued, ie := time.Parse(time.RFC3339, manifest.IssuedAt)
	expires, ee := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if ie != nil || ee != nil || issued.UTC().Format(time.RFC3339) != manifest.IssuedAt || expires.UTC().Format(time.RFC3339) != manifest.ExpiresAt || !expires.After(issued) || expires.Sub(issued) > 30*24*time.Hour {
		return nil, ErrMetadata
	}
	if !expires.After(now) || issued.After(now.Add(5*time.Minute)) {
		return nil, ErrExpired
	}
	a := manifest.Artifact
	expected := "FreeTurn-Setup-" + manifest.Version + "-" + manifest.Channel + "-win-x64.exe"
	if a.Name != expected || a.URL != trust.Origin+"/windows/"+expected || a.Bytes < 2 || a.Bytes > MaxArtifact || !lowerSHA(a.SHA256) {
		return nil, ErrMetadata
	}
	return &manifest, nil
}

// VerifyArtifact validates this open reader only. Callers must not later launch
// a replaceable path on the strength of a past hash check.
func VerifyArtifact(reader io.Reader, a Artifact) error {
	if a.Bytes < 2 || a.Bytes > MaxArtifact || !lowerSHA(a.SHA256) {
		return ErrArtifact
	}
	var prefix [2]byte
	if _, e := io.ReadFull(reader, prefix[:]); e != nil || string(prefix[:]) != "MZ" {
		return ErrArtifact
	}
	h := sha256.New()
	h.Write(prefix[:])
	n, e := io.Copy(h, io.LimitReader(reader, a.Bytes-2+1))
	if e != nil || n+2 != a.Bytes || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return ErrArtifact
	}
	return nil
}
