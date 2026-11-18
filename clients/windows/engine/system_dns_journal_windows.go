package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"

	"golang.org/x/crypto/hkdf"
	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
)

const fakeDNSJournalPurpose = "FreeTurn DNS identities v1"
const fakeDNSJournalHeader = "FTMFDN2\n"
const legacyFakeDNSJournalHeader = "FTMFDN1\n"
const maxFakeDNSJournalBytes = 64 * 1024 * 1024

type fakeDNSIdentity struct {
	V    int        `json:"v"`
	Host string     `json:"host,omitempty"` // accepted only during v1 migration
	ID   string     `json:"id,omitempty"`
	IP   netip.Addr `json:"ip"`
}
type fakeDNSJournal struct {
	file     *os.File
	size     int64
	failed   bool
	aead     cipher.AEAD
	headPath string
	entries  uint64
	identity func(string) string
}

// Append-only AES-256-GCM, DPAPI-wrapped key, bounded, fsync-before-answer.
// One DPAPI operation per open (not per hostname) keeps reconnects fast. No route
// decisions or resolved IPs survive a profile/policy change. A corrupt/missing
// required journal is NEVER silently reset, which could alias old app DNS IPs.
func openFakeDNSJournal(path string, required bool) (*fakeDNS, *fakeDNSJournal, error) {
	return openFakeDNSJournalContext(context.Background(), path, required)
}
func openFakeDNSJournalContext(ctx context.Context, path string, required bool) (*fakeDNS, *fakeDNSJournal, error) {
	invalid := func() (*fakeDNS, *fakeDNSJournal, error) { return nil, nil, errors.New("SYSTEM_DNS_CACHE_INVALID") }
	if ctx.Err() != nil {
		return nil, nil, errors.New("SYSTEM_ROUTING_CANCELLED")
	}
	if noReparse(path) != nil {
		return invalid()
	}
	headPath := path + ".head"
	if noReparse(headPath) != nil {
		return invalid()
	}
	created := false
	if _, e := os.Stat(path); os.IsNotExist(e) {
		if required {
			return invalid()
		}
		if _, e := os.Stat(headPath); !os.IsNotExist(e) {
			return invalid()
		}
		key := make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return invalid()
		}
		wrapped, e := dpapi.Encrypt(key, fakeDNSJournalPurpose)
		clear(key)
		if e != nil || len(wrapped) > 4096 {
			return invalid()
		}
		header := make([]byte, len(fakeDNSJournalHeader)+4+len(wrapped))
		copy(header, []byte(fakeDNSJournalHeader))
		binary.LittleEndian.PutUint32(header[len(fakeDNSJournalHeader):], uint32(len(wrapped)))
		copy(header[len(fakeDNSJournalHeader)+4:], wrapped)
		if atomicPrivate(path, header) != nil {
			return nil, nil, errors.New("SYSTEM_DNS_CACHE_WRITE_FAILED")
		}
		created = true
	} else if e != nil {
		return invalid()
	}
	f, e := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	if e != nil {
		return invalid()
	}
	ok := false
	defer func() {
		if !ok && f != nil {
			f.Close()
		}
	}()
	stat, e := f.Stat()
	if e != nil || stat.Size() < int64(len(fakeDNSJournalHeader)) || stat.Size() > maxFakeDNSJournalBytes {
		return invalid()
	}
	reader := bufio.NewReader(f)
	header := make([]byte, len(fakeDNSJournalHeader))
	if _, e := io.ReadFull(reader, header); e != nil || string(header) != fakeDNSJournalHeader && string(header) != legacyFakeDNSJournalHeader {
		return invalid()
	}
	legacy := string(header) == legacyFakeDNSJournalHeader
	var keySize [4]byte
	if _, e = io.ReadFull(reader, keySize[:]); e != nil {
		return invalid()
	}
	keyLength := binary.LittleEndian.Uint32(keySize[:])
	if keyLength < 1 || keyLength > 4096 {
		return invalid()
	}
	wrapped := make([]byte, keyLength)
	if _, e = io.ReadFull(reader, wrapped); e != nil {
		return invalid()
	}
	key, e := dpapi.Decrypt(wrapped, fakeDNSJournalPurpose)
	if e != nil || len(key) != 32 {
		return invalid()
	}
	block, e := aes.NewCipher(key)
	hmacKey := make([]byte, 32)
	_, keyErr := io.ReadFull(hkdf.New(sha256.New, key, nil, []byte("FreeTurn opaque DNS identities v2")), hmacKey)
	clear(key)
	if e != nil || keyErr != nil {
		return invalid()
	}
	aead, e := cipher.NewGCMWithRandomNonce(block)
	if e != nil {
		return invalid()
	}
	leases := newFakeDNS(maxFakeDNSIdentities)
	identity := func(host string) string {
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write([]byte(host))
		return hex.EncodeToString(mac.Sum(nil))
	}
	leases.identity = identity
	for {
		if ctx.Err() != nil {
			return nil, nil, errors.New("SYSTEM_ROUTING_CANCELLED")
		}
		var length [4]byte
		n, e := io.ReadFull(reader, length[:])
		if e == io.EOF && n == 0 {
			break
		}
		if e != nil {
			return invalid()
		}
		size := binary.LittleEndian.Uint32(length[:])
		if size < 1 || size > 4096 || len(leases.byIP) >= leases.limit {
			return invalid()
		}
		cipher := make([]byte, size)
		if _, e = io.ReadFull(reader, cipher); e != nil {
			return invalid()
		}
		plain, e := aead.Open(nil, nil, cipher, nil)
		if e != nil || len(plain) > 1024 || !uniqueJSON(plain) {
			return invalid()
		}
		var record fakeDNSIdentity
		d := json.NewDecoder(bytes.NewReader(plain))
		d.DisallowUnknownFields()
		if d.Decode(&record) != nil || d.Decode(new(any)) != io.EOF {
			return invalid()
		}
		if legacy {
			normalized, e := routingDomain(record.Host)
			if record.V != 1 || record.ID != "" || e != nil || normalized != record.Host {
				return invalid()
			}
			record.ID = identity(record.Host)
		} else {
			rawID, e := hex.DecodeString(record.ID)
			if record.V != 2 || record.Host != "" || e != nil || len(rawID) != 32 || hex.EncodeToString(rawID) != record.ID {
				return invalid()
			}
		}
		expected := leases.next.Next()
		if record.IP != expected || !systemFakeRange.Contains(expected) || netip.MustParseAddr("198.19.255.251").Less(expected) {
			return invalid()
		}
		if _, duplicate := leases.byID[record.ID]; duplicate {
			return invalid()
		}
		leases.next = expected
		leases.byID[record.ID] = record.IP
		leases.byIP[record.IP] = fakeDNSLease{}
	}
	journal := &fakeDNSJournal{file: f, size: stat.Size(), aead: aead, headPath: headPath, entries: uint64(len(leases.byIP)), identity: identity}
	// Durable high-water mark detects truncation at a valid record boundary.
	// An uncommitted complete tail is kept/reserved, never reused.
	if created {
		if journal.saveHead() != nil {
			return nil, nil, errors.New("SYSTEM_DNS_CACHE_WRITE_FAILED")
		}
	} else {
		i, e := os.Stat(headPath)
		if e != nil || i.Size() > 4096 {
			return invalid()
		}
		sealed, e := os.ReadFile(headPath)
		if e != nil {
			return invalid()
		}
		plain, e := aead.Open(nil, nil, sealed, []byte("FTMFDN1/head"))
		if e != nil || len(plain) != 8 {
			return invalid()
		}
		high := binary.LittleEndian.Uint64(plain)
		if high > journal.entries {
			return invalid()
		}
		if high < journal.entries && journal.saveHead() != nil {
			return nil, nil, errors.New("SYSTEM_DNS_CACHE_WRITE_FAILED")
		}
	}
	if legacy {
		// Same DPAPI/AES key and high-water mark. Atomic replacement changes only
		// record format; either complete v1 or complete v2 survives interruption.
		encoded := make([]byte, len(fakeDNSJournalHeader)+4+len(wrapped))
		copy(encoded, []byte(fakeDNSJournalHeader))
		binary.LittleEndian.PutUint32(encoded[len(fakeDNSJournalHeader):], uint32(len(wrapped)))
		copy(encoded[len(fakeDNSJournalHeader)+4:], wrapped)
		ids := make(map[netip.Addr]string, len(leases.byID))
		for id, ip := range leases.byID {
			ids[ip] = id
		}
		for ip := netip.MustParseAddr("198.18.0.2"); !leases.next.Less(ip); ip = ip.Next() {
			if ctx.Err() != nil {
				return nil, nil, errors.New("SYSTEM_ROUTING_CANCELLED")
			}
			record, err := journal.encode(ids[ip], ip)
			if err != nil || len(encoded)+len(record) > maxFakeDNSJournalBytes {
				return invalid()
			}
			encoded = append(encoded, record...)
		}
		if f.Close() != nil || atomicPrivate(path, encoded) != nil {
			return nil, nil, errors.New("SYSTEM_DNS_CACHE_WRITE_FAILED")
		}
		f, e = os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
		if e != nil {
			return invalid()
		}
		journal.file = f
		journal.size = int64(len(encoded))
	}
	leases.persist = journal.append
	ok = true
	return leases, journal, nil
}

// Called only while fakeDNS.mu is held. A partial write poisons this journal
// instance; later answers cannot reuse an uncommitted/possibly written IP.
func (j *fakeDNSJournal) append(host string, ip netip.Addr) error {
	fail := func() error { j.failed = true; return errors.New("SYSTEM_DNS_CACHE_WRITE_FAILED") }
	if j.failed {
		return fail()
	}
	record, e := j.encode(j.identity(host), ip)
	if e != nil {
		return fail()
	}
	if j.size+int64(len(record)) > maxFakeDNSJournalBytes {
		return fail()
	}
	n, e := j.file.Write(record)
	if e != nil || n != len(record) || j.file.Sync() != nil {
		return fail()
	}
	j.size += int64(n)
	j.entries++
	if j.saveHead() != nil {
		return fail()
	}
	return nil
}
func (j *fakeDNSJournal) encode(id string, ip netip.Addr) ([]byte, error) {
	plain, e := json.Marshal(fakeDNSIdentity{V: 2, ID: id, IP: ip})
	if e != nil {
		return nil, e
	}
	sealed := j.aead.Seal(nil, nil, plain, nil)
	if len(sealed) > 4096 {
		return nil, errSystemRouting
	}
	record := make([]byte, 4+len(sealed))
	binary.LittleEndian.PutUint32(record[:4], uint32(len(sealed)))
	copy(record[4:], sealed)
	return record, nil
}
func (j *fakeDNSJournal) saveHead() error {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], j.entries)
	sealed := j.aead.Seal(nil, nil, raw[:], []byte("FTMFDN1/head"))
	return atomicPrivate(j.headPath, sealed)
}
func (j *fakeDNSJournal) Close() error {
	if j.file.Close() != nil {
		return errors.New("SYSTEM_DNS_CACHE_WRITE_FAILED")
	}
	return nil
}
