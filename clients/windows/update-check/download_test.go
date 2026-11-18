package updatecheck

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadOverTLSRejectsRedirectsUntrustedAndCorruptContent(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://updates.example.com"
	const feedPath = "/windows/preview/release.json"
	const file = "FreeTurn-Setup-0.28.0-preview-win-x64.exe"
	const packagePath = "/windows/" + file
	trust := Trust{PublicKey: public, Origin: origin, Channel: "preview"}
	artifact := []byte("MZ-SYNTHETIC-NEVER-EXECUTED")
	hash := sha256.Sum256(artifact)
	now := time.Now().UTC().Truncate(time.Second)
	manifest := Manifest{Schema: 1, App: "freeturn-windows", Platform: "windows-amd64", Channel: "preview",
		Version: "0.28.0", Sequence: 7, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Artifact: Artifact{Name: file, URL: origin + packagePath,
			Bytes: int64(len(artifact)), SHA256: hex.EncodeToString(hash[:])}}
	payload, _ := json.Marshal(manifest)
	encode := base64.RawURLEncoding.EncodeToString
	signature := ed25519.Sign(private, append([]byte(signatureContext), payload...))
	valid, _ := json.Marshal(Envelope{Payload: encode(payload), Signature: encode(signature)})
	var mode atomic.Int32
	var unexpected atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case feedPath:
			switch mode.Load() {
			case 1:
				http.Redirect(w, r, "/unintended", http.StatusFound)
			case 2:
				w.Header().Set("Content-Length", strconv.Itoa(MaxEnvelope+1))
			case 3:
				w.Header().Set("Content-Encoding", "gzip")
				w.Write(valid)
			case 4:
				w.Write(bytes.Replace(valid, []byte(encode(signature)), []byte(encode(make([]byte, 64))), 1))
			default:
				w.Write(valid)
			}
		case packagePath:
			switch mode.Load() {
			case 5:
				http.Redirect(w, r, "/unintended", http.StatusTemporaryRedirect)
			case 6:
				body := bytes.Clone(artifact)
				body[len(body)-1] ^= 1
				w.Write(body)
			case 7:
				w.(http.Flusher).Flush() // The exact length must also be enforced on chunked responses.
				w.Write(append(bytes.Clone(artifact), 'X'))
			default:
				w.Write(artifact)
			}
		default:
			unexpected.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx := context.Background()
	client := server.Client().Transport.(*http.Transport).Clone()
	d := newDownloader(client, func() time.Time { return now })
	directory := t.TempDir()
	untrusted := client.Clone()
	untrusted.TLSClientConfig.RootCAs = x509.NewCertPool()
	if _, err := newDownloader(untrusted, time.Now).Check(ctx, trust, "0.27.0", 6); !errors.Is(err, ErrDownload) {
		t.Fatal("untrusted TLS server accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := d.Check(cancelled, trust, "0.27.0", 6); !errors.Is(err, ErrDownload) {
		t.Fatal("cancelled fetch accepted")
	}
	for m, want := range map[int32]error{1: ErrDownload, 2: ErrDownload, 3: ErrDownload, 4: ErrSignature} {
		mode.Store(m)
		if _, err := d.Check(ctx, trust, "0.27.0", 6); !errors.Is(err, want) {
			t.Fatalf("feed case %d: %v", m, err)
		}
	}
	mode.Store(0)
	release, err := d.Check(ctx, trust, "0.27.0", 6)
	if err != nil || release.Metadata().Version != manifest.Version {
		t.Fatalf("valid feed: %v", err)
	}
	for _, m := range []int32{5, 6, 7} {
		mode.Store(m)
		if _, err := d.Download(ctx, release, directory); err == nil {
			t.Fatalf("artifact case %d accepted", m)
		}
		files, err := os.ReadDir(directory)
		if err != nil || len(files) != 0 {
			t.Fatal("failed download left staging data")
		}
	}
	mode.Store(0)
	staged, err := d.Download(ctx, release, directory)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := io.ReadAll(staged)
	if err != nil || !bytes.Equal(verified, artifact) || staged.Close() != nil {
		t.Fatal("staged bytes or close failed")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 0 || unexpected.Load() != 0 {
		t.Fatal("temporary file retained or redirect followed")
	}
	now = now.Add(time.Hour)
	if _, err := d.Download(ctx, release, directory); !errors.Is(err, ErrExpired) {
		t.Fatal("expired candidate downloaded")
	}
}
