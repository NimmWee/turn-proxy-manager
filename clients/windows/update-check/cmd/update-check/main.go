// Developer-facing offline verifier. No download, elevation, execution or state.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	check "freeturn.local/updatecheck"
)

type config struct {
	PublicKey string `json:"publicKey"`
	Origin    string `json:"origin"`
	Channel   string `json:"channel"`
}

func openLocalFile(path string, limit int64) (*os.File, error) {
	full, e := filepath.Abs(path)
	if e != nil || len(filepath.VolumeName(full)) != 2 || full[1] != ':' || strings.Contains(full[2:], ":") {
		return nil, os.ErrInvalid
	}
	info, e := os.Lstat(full)
	if e != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, os.ErrInvalid
	}
	f, e := os.Open(full)
	if e != nil {
		return nil, e
	}
	info, e = f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > limit {
		f.Close()
		return nil, os.ErrInvalid
	}
	return f, nil
}

func boundedFile(path string, limit int64) ([]byte, error) {
	f, e := openLocalFile(path, limit)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if len(raw) > int(limit) {
		return nil, io.ErrShortBuffer
	}
	return raw, e
}

func main() {
	flags := flag.NewFlagSet("update-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	trustPath := flags.String("trust", "", "Out-of-band trusted public key/origin/channel JSON")
	envelopePath := flags.String("release", "", "Signed release envelope")
	artifactPath := flags.String("artifact", "", "Local installer bytes; never executed")
	current := flags.String("current-version", "", "Installed version")
	sequence := flags.Uint64("accepted-sequence", 0, "Previously accepted revision fence")
	finish := func(code string) {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "error": code, "downloaded": false, "executed": false})
		os.Exit(1)
	}
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || *trustPath == "" || *envelopePath == "" || *artifactPath == "" || *current == "" {
		finish("UPDATE_INPUT_REQUIRED")
	}
	raw, e := boundedFile(*trustPath, 4096)
	var wire config
	if e != nil || !check.StrictJSON(raw, &wire) {
		finish("UPDATE_TRUST_REQUIRED")
	}
	publicKey, e := base64.RawURLEncoding.Strict().DecodeString(wire.PublicKey)
	if e != nil || len(publicKey) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(publicKey) != wire.PublicKey {
		finish("UPDATE_TRUST_REQUIRED")
	}
	raw, e = boundedFile(*envelopePath, check.MaxEnvelope)
	if e != nil {
		finish("UPDATE_METADATA_INVALID")
	}
	manifest, e := check.Verify(raw, check.Trust{PublicKey: publicKey, Origin: wire.Origin, Channel: wire.Channel}, *current, *sequence, time.Now())
	if e != nil {
		finish(e.Error())
	}
	file, e := openLocalFile(*artifactPath, check.MaxArtifact)
	if e != nil {
		finish("UPDATE_FILE_UNAVAILABLE")
	}
	defer file.Close()
	if check.VerifyArtifact(file, manifest.Artifact) != nil {
		finish("UPDATE_PACKAGE_MISMATCH")
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "version": manifest.Version, "channel": manifest.Channel, "sequence": manifest.Sequence, "bytes": manifest.Artifact.Bytes, "downloaded": false, "executed": false, "verificationScope": "offline-check-time-only"})
}
