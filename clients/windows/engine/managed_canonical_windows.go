package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Server v1 hashes Python json.dumps(ensure_ascii=False, sort_keys=True,
// separators=(",", ":")). Standard Go JSON additionally escapes U+2028/U+2029;
// writing strings directly avoids corrupting literal backslash-u sequences.
func canonicalManagedJSON(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) || !uniqueJSON(raw) {
		return nil, errors.New("MANAGED_CONFIG_INVALID")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("MANAGED_CONFIG_INVALID")
	}
	var out bytes.Buffer
	quote := func(s string) error {
		if strings.ContainsRune(s, utf8.RuneError) {
			return errors.New("MANAGED_CONFIG_INVALID")
		}
		out.WriteByte('"')
		for _, r := range s {
			switch r {
			case '\\', '"':
				out.WriteByte('\\')
				out.WriteRune(r)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 32 {
					fmt.Fprintf(&out, `\u%04x`, r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
		return nil
	}
	var write func(any) error
	write = func(v any) error {
		switch v := v.(type) {
		case nil:
			out.WriteString("null")
		case bool:
			out.WriteString(strconv.FormatBool(v))
		case string:
			return quote(v)
		case json.Number:
			n, e := v.Int64()
			if e != nil {
				return e
			}
			out.WriteString(strconv.FormatInt(n, 10))
		case []any:
			out.WriteByte('[')
			for i, item := range v {
				if i > 0 {
					out.WriteByte(',')
				}
				if e := write(item); e != nil {
					return e
				}
			}
			out.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			out.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					out.WriteByte(',')
				}
				if e := quote(k); e != nil {
					return e
				}
				out.WriteByte(':')
				if e := write(v[k]); e != nil {
					return e
				}
			}
			out.WriteByte('}')
		default:
			return errors.New("MANAGED_CONFIG_INVALID")
		}
		return nil
	}
	if write(value) != nil {
		return nil, errors.New("MANAGED_CONFIG_INVALID")
	}
	return out.Bytes(), nil
}
