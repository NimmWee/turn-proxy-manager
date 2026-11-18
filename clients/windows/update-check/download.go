package updatecheck

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	ErrDownload = errors.New("UPDATE_DOWNLOAD_FAILED")
	ErrStaging  = errors.New("UPDATE_STAGING_FAILED")
)

// Release represents a candidate checked against explicit publisher trust.
// The signed artifact location and bytes are immutable outside this package.
type Release struct {
	manifest  Manifest
	expiresAt time.Time
}

func (r *Release) Metadata() Manifest { return r.manifest }

// Downloader checks HTTPS responses with normal TLS validation and requests
// only the configured feed and the verified, same-origin package URL.
type Downloader struct {
	client *http.Client
	now    func() time.Time
}

func NewDownloader() *Downloader {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return newDownloader(&http.Transport{
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		DisableCompression:     true,
		MaxConnsPerHost:        2,
		MaxIdleConns:           2,
		IdleConnTimeout:        30 * time.Second,
		ForceAttemptHTTP2:      true,
	}, time.Now)
}

func newDownloader(transport *http.Transport, now func() time.Time) *Downloader {
	return &Downloader{client: &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now: now}
}

func (d *Downloader) get(ctx context.Context, address string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, ErrDownload
	}
	request.Header.Set("Accept-Encoding", "identity")
	response, err := d.client.Do(request)
	if err != nil {
		return nil, ErrDownload
	}
	encoding := response.Header.Get("Content-Encoding")
	if response.StatusCode != http.StatusOK || (encoding != "" && encoding != "identity") {
		response.Body.Close()
		return nil, ErrDownload
	}
	return response, nil
}

// Check fetches the channel manifest only. The caller supplies the installed
// version and the retained sequence fence from its own trusted state.
func (d *Downloader) Check(ctx context.Context, trust Trust, currentVersion string, acceptedSequence uint64) (*Release, error) {
	if !validTrust(trust) {
		return nil, ErrTrust
	}
	if _, ok := version(currentVersion); !ok {
		return nil, ErrMetadata
	}
	if acceptedSequence > math.MaxInt64 {
		return nil, ErrRollback
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	response, err := d.get(ctx, trust.Origin+"/windows/"+trust.Channel+"/release.json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength > MaxEnvelope {
		return nil, ErrDownload
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxEnvelope+1))
	if err != nil || len(raw) > MaxEnvelope {
		return nil, ErrDownload
	}
	manifest, err := Verify(raw, trust, currentVersion, acceptedSequence, d.now())
	if err != nil {
		return nil, err
	}
	expiresAt, _ := time.Parse(time.RFC3339, manifest.ExpiresAt) // Checked by Verify.
	return &Release{manifest: *manifest, expiresAt: expiresAt}, nil
}

// Download streams an accepted candidate into a temporary file inside the
// caller's private directory. It returns an open reader after verifying the
// file's exact bytes. The caller must close it. Neither the path nor an
// executable operation is exposed, and the revision fence is not changed.
func (d *Downloader) Download(ctx context.Context, release *Release, privateDirectory string) (io.ReadCloser, error) {
	if release == nil || release.expiresAt.IsZero() {
		return nil, ErrMetadata
	}
	if !release.expiresAt.After(d.now()) {
		return nil, ErrExpired
	}
	if !filepath.IsAbs(privateDirectory) {
		return nil, ErrStaging
	}
	dir, err := os.Lstat(privateDirectory)
	if err != nil || !dir.IsDir() || dir.Mode()&os.ModeSymlink != 0 {
		return nil, ErrStaging
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	artifact := release.manifest.Artifact
	response, err := d.get(ctx, artifact.URL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.ContentLength != -1 && response.ContentLength != artifact.Bytes {
		return nil, ErrArtifact
	}
	file, err := os.CreateTemp(privateDirectory, "freeturn-update-*.part")
	if err != nil {
		return nil, ErrStaging
	}
	staged := &temporaryPackage{file: file}
	verified := false
	defer func() {
		if !verified {
			staged.Close()
		}
	}()

	n, err := io.Copy(file, io.LimitReader(response.Body, artifact.Bytes+1))
	if err != nil || ctx.Err() != nil {
		return nil, ErrDownload
	}
	if n != artifact.Bytes {
		return nil, ErrArtifact
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrStaging
	}
	if err := VerifyArtifact(file, artifact); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrDownload
	}
	if !release.expiresAt.After(d.now()) {
		return nil, ErrExpired
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, ErrStaging
	}
	verified = true
	return staged, nil
}

type temporaryPackage struct {
	file     *os.File
	once     sync.Once
	closeErr error
}

func (p *temporaryPackage) Read(buf []byte) (int, error) {
	n, err := p.file.Read(buf)
	if err != nil && err != io.EOF {
		return n, ErrStaging
	}
	return n, err
}

func (p *temporaryPackage) Close() error {
	p.once.Do(func() {
		closeErr := p.file.Close()
		removeErr := os.Remove(p.file.Name())
		if closeErr != nil || removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			p.closeErr = ErrStaging
		}
	})
	return p.closeErr
}
