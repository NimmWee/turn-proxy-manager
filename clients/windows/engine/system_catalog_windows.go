package main

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"time"
)

// Compiled from independently pinned, licensed data by prepare_system_routing.py.
// Runtime never downloads routing rules or executes supplier code.
//
//go:embed routingdata/catalog.json
var systemCatalogJSON []byte

const systemCatalogSHA256 = "199db1b643f43214fe0988cd1cfb3e7a12fcc3c229c3351046d2fc020bd96e70"

type systemGeoIPInfo struct {
	Provider     string `json:"provider"`
	Release      string `json:"release"`
	Country      string `json:"country"`
	License      string `json:"license"`
	Attribution  string `json:"attribution"`
	URL          string `json:"url"`
	SourceSHA256 string `json:"sourceSHA256"`
	IPv4Prefixes int    `json:"ipv4Prefixes"`
}

func loadSystemCatalog() (*systemCatalog, error) {
	return decodeSystemCatalog(systemCatalogJSON, systemCatalogSHA256)
}

func decodeSystemCatalog(raw []byte, expected string) (*systemCatalog, error) {
	sum := sha256.Sum256(raw)
	if len(raw) > 2*1024*1024 || hex.EncodeToString(sum[:]) != expected {
		return nil, errors.New("SYSTEM_ROUTING_CATALOG_HASH")
	}
	var data struct {
		V        int               `json:"v"`
		RU       presetPatterns    `json:"ru"`
		YouTube  presetPatterns    `json:"youtube"`
		Push     presetPatterns    `json:"push"`
		Checks   presetPatterns    `json:"connectivity"`
		Prefixes []string          `json:"ruPrefixes"`
		Sources  map[string]string `json:"sources"`
		Meaning  string            `json:"countryAddressMeaning"`
		GeoIP    systemGeoIPInfo   `json:"geoIP"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if !uniqueJSON(raw) || d.Decode(&data) != nil || d.Decode(new(any)) != io.EOF || data.V != 1 {
		return nil, errSystemRouting
	}
	info := data.GeoIP
	_, dateErr := time.Parse("2006-01", info.Release)
	hash, hashErr := hex.DecodeString(info.SourceSHA256)
	if info.Provider != "DB-IP Lite" || info.Country != "RU" || info.License != "CC-BY-4.0" || info.Attribution != "IP Geolocation by DB-IP" || info.URL != "https://db-ip.com/" || dateErr != nil || hashErr != nil || len(hash) != 32 || hex.EncodeToString(hash) != info.SourceSHA256 || info.SourceSHA256 != data.Sources["dbipCountry"] || info.IPv4Prefixes != len(data.Prefixes) || info.IPv4Prefixes < 1 || info.IPv4Prefixes > 200000 {
		return nil, errSystemRouting
	}
	for _, patterns := range []presetPatterns{data.RU, data.YouTube, data.Push, data.Checks} {
		if len(patterns.Suffix)+len(patterns.Exact)+len(patterns.Keyword) > 20000 || len(patterns.Regex) > 256 {
			return nil, errSystemRouting
		}
		for _, list := range [][]string{patterns.Suffix, patterns.Exact, patterns.Keyword, patterns.Regex} {
			for _, v := range list {
				if len(v) == 0 || len(v) > 512 {
					return nil, errSystemRouting
				}
			}
		}
	}
	c := &systemCatalog{RU: data.RU, YouTube: data.YouTube, Push: data.Push, Checks: data.Checks, GeoIP: info}
	protected := []netip.Prefix{}
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32"} {
		protected = append(protected, netip.MustParsePrefix(s))
	}
	var previous netip.Prefix
	for _, s := range data.Prefixes {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() || p != p.Masked() || previous.IsValid() && (previous.Addr().Compare(p.Addr()) >= 0 || previous.Overlaps(p)) {
			return nil, errSystemRouting
		}
		for _, reserved := range protected {
			if p.Overlaps(reserved) {
				return nil, errSystemRouting
			}
		}
		previous = p
		c.RUPrefixes = append(c.RUPrefixes, p)
	}
	return c, nil
}
