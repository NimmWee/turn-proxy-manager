package main

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"io"
)

const maxSystemMessage = 512 * 1024

type systemCatalogUpdate struct {
	SHA256 string `json:"sha256"`
	Gzip   string `json:"gzip"`
}

func updatedSystemCatalog(update *systemCatalogUpdate) (*systemCatalog, error) {
	if update == nil {
		return loadSystemCatalog()
	}
	invalid := errors.New("SYSTEM_ROUTING_CATALOG_HASH")
	if len(update.Gzip) > 170000 {
		return nil, invalid
	}
	packed, e := base64.StdEncoding.Strict().DecodeString(update.Gzip)
	if e != nil {
		return nil, invalid
	}
	r, e := gzip.NewReader(bytes.NewReader(packed))
	if e != nil {
		return nil, invalid
	}
	defer r.Close()
	raw, e := io.ReadAll(io.LimitReader(r, 1024*1024+1))
	if e != nil || len(raw) > 1024*1024 {
		return nil, invalid
	}
	catalog, e := decodeSystemCatalog(raw, update.SHA256)
	if e != nil {
		return nil, e
	}
	baseline, e := loadSystemCatalog()
	if e != nil || catalog.GeoIP.Release < baseline.GeoIP.Release {
		return nil, invalid
	}
	return catalog, nil
}
