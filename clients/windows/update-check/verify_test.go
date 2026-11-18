package updatecheck

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSignedCandidateAndArtifactRejectTamperRollbackAndSubstitution(t *testing.T) {
	pub, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("fixture key")
	}
	now := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	artifact := []byte("MZ-SYNTHETIC-NEVER-EXECUTED")
	digest := sha256.Sum256(artifact)
	m := Manifest{Schema: 1, App: "freeturn-windows", Platform: "windows-amd64", Channel: "preview", Version: "0.26.0", Sequence: 7, IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339), Artifact: Artifact{Name: "FreeTurn-Setup-0.26.0-preview-win-x64.exe", URL: "https://updates.example.invalid/windows/FreeTurn-Setup-0.26.0-preview-win-x64.exe", Bytes: int64(len(artifact)), SHA256: hex.EncodeToString(digest[:])}}
	trust := Trust{PublicKey: pub, Origin: "https://updates.example.invalid", Channel: "preview"}
	sign := func(payload []byte) []byte {
		sig := ed25519.Sign(private, append([]byte(signatureContext), payload...))
		raw, _ := json.Marshal(Envelope{Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(sig)})
		return raw
	}
	encode := func(value Manifest) []byte { raw, _ := json.Marshal(value); return sign(raw) }
	candidate, e := Verify(encode(m), trust, "0.25.0", 6, now)
	if e != nil || candidate.Version != "0.26.0" || VerifyArtifact(bytes.NewReader(artifact), candidate.Artifact) != nil {
		t.Fatal("valid signed candidate/bytes refused")
	}
	if VerifyArtifact(strings.NewReader("MZ-TAMPERED"), candidate.Artifact) == nil || VerifyArtifact(bytes.NewReader(append(artifact, 'X')), candidate.Artifact) == nil {
		t.Fatal("artifact tampering accepted")
	}
	for _, change := range []func(*Manifest){
		func(v *Manifest) { v.Version = "0.25.0" }, func(v *Manifest) { v.Sequence = 6 }, func(v *Manifest) { v.Channel = "stable" },
		func(v *Manifest) { v.App = "other-app" }, func(v *Manifest) { v.Platform = "windows-arm64" }, func(v *Manifest) { v.Version = "00.26.0" },
		func(v *Manifest) { v.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339) }, func(v *Manifest) { v.IssuedAt = now.Add(time.Hour).Format(time.RFC3339) },
		func(v *Manifest) { v.Artifact.URL = "https://evil.example.invalid/windows/" + v.Artifact.Name },
		func(v *Manifest) { v.Artifact.URL += "?redirect=evil" }, func(v *Manifest) { v.Artifact.Name = "../payload.exe" },
		func(v *Manifest) { v.Artifact.Bytes = 257 << 20 }, func(v *Manifest) { v.Artifact.SHA256 = strings.Repeat("A", 64) },
	} {
		bad := m
		change(&bad)
		if _, e := Verify(encode(bad), trust, "0.25.0", 6, now); e == nil {
			t.Fatal("signed but incompatible/stale candidate accepted")
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	for _, key := range []ed25519.PublicKey{nil, make([]byte, 32), other} {
		bad := trust
		bad.PublicKey = key
		if _, e := Verify(encode(m), bad, "0.25.0", 6, now); e == nil {
			t.Fatal("missing/wrong trust accepted")
		}
	}
	raw, _ := json.Marshal(m)
	duplicate := append([]byte(`{"schema":1,`), raw[1:]...)
	if _, e := Verify(sign(duplicate), trust, "0.25.0", 6, now); e == nil {
		t.Fatal("ambiguous signed JSON accepted")
	}
	corrupt := encode(m)
	corrupt[len(corrupt)/2] ^= 1
	if _, e := Verify(corrupt, trust, "0.25.0", 6, now); e == nil {
		t.Fatal("modified envelope accepted")
	}
}
