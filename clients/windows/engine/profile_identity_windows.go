package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Owner-pipe correlation only. Never substitute this digest for profile validation.
func profileIdentity(share string) string {
	digest := sha256.Sum256([]byte("FreeTurn profile identity v1\x00" + strings.TrimSpace(share)))
	return hex.EncodeToString(digest[:])
}

func validProfileIdentity(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

func runtimeIdentity(state runtimeState, options connectionOptions, pid int, now time.Time) (string, uint64) {
	if pid <= 0 || state.PID != pid || state.Updated > now.Unix() || now.Unix()-state.Updated > 6 ||
		options.AttemptID == 0 || state.EventSession != options.AttemptID ||
		!validProfileIdentity(state.ProfileIdentity) || state.ProfileIdentity != options.ProfileIdentity || validRuntimePath(state, options) != nil {
		return "", 0
	}
	return state.ProfileIdentity, state.EventSession
}

func matchesRuntime(r response, identity string, attempt uint64, epochs ...uint64) bool {
	epoch := uint64(0)
	if len(epochs) > 0 {
		epoch = epochs[0]
	}
	return r.OK && r.TunnelActive && !r.PathPending && r.PathEpoch == epoch && validProfileIdentity(identity) && attempt != 0 &&
		r.RuntimeProfileIdentity == identity && r.ConnectionID == attempt
}
