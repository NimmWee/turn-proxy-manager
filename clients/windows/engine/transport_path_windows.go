package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type pathJournal struct {
	Version  int    `json:"version"`
	Attempt  uint64 `json:"attempt"`
	Identity string `json:"identity"`
	Epoch    uint64 `json:"epoch"`
	Target   string `json:"target"`
}

func validPath(path string) bool { return path == "direct" || path == "relay" }
func pathEgressReady(state runtimeState, confirmedAt int64) bool {
	return state.PathStartedAt > 0 && confirmedAt > state.PathStartedAt+8
}
func canonicalPath(raw string) (string, error) {
	p, err := parseProfile(raw)
	if err != nil || p.Kind != "wireguard" {
		return "", errProfile
	}
	var core struct {
		Provider string `json:"provider"`
	}
	if json.Unmarshal([]byte(p.Core), &core) != nil {
		return "", errProfile
	}
	if core.Provider == "direct" {
		return "direct", nil
	}
	return "relay", nil
}
func coreForPath(raw, path string, advanced bool, forceManual ...bool) (string, error) {
	p, err := parseProfile(raw)
	if err != nil || p.Kind != "wireguard" || !validPath(path) {
		return "", errProfile
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(strings.TrimSpace(raw), "freeturn://"))
	if err != nil {
		return "", errProfile
	}
	var share shareProfile
	if json.Unmarshal(data, &share) != nil || share.VK == "" {
		return "", errProfile
	}
	var core map[string]any
	if json.Unmarshal([]byte(p.Core), &core) != nil {
		return "", errProfile
	}
	vk := core["vk"].(map[string]any)
	turn := core["turn"].(map[string]any)
	core["provider"] = "vk"
	vk["links"] = []string{share.VK}
	vk["manualCaptcha"] = share.MCap
	if path == "direct" {
		core["provider"] = "direct"
		turn["n"] = 1
		vk["links"] = []string{}
		vk["manualCaptcha"] = false
	}
	encoded, err := json.Marshal(core)
	if err != nil {
		return "", errProfile
	}
	return configureCaptcha(string(encoded), advanced, forceManual...)
}
func decodePathJournal(data []byte) (*pathJournal, error) {
	if len(data) > 1024 || !uniqueJSON(data) {
		return nil, errors.New("PATH_STATE_INVALID")
	}
	var value pathJournal
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF || value.Version != 1 || value.Attempt == 0 || !validProfileIdentity(value.Identity) || value.Epoch < 1 || value.Epoch > 2 || !validPath(value.Target) || value.Epoch == 1 && value.Target != "relay" || value.Epoch == 2 && value.Target != "direct" {
		return nil, errors.New("PATH_STATE_INVALID")
	}
	return &value, nil
}
func loadPathJournal(dir string, attempt uint64, identity string) (*pathJournal, error) {
	data, err := readSecret(filepath.Join(dir, "transport-path.dpapi"), "FreeTurn transport path v1")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("PATH_STATE_INVALID")
	}
	value, err := decodePathJournal(data)
	if err != nil {
		return nil, err
	}
	if value.Attempt != attempt || value.Identity != identity {
		return nil, nil
	}
	return value, nil
}
func canSwitchPath(r response, id string, attempt, epoch uint64, target string) bool {
	return r.AutoPaths && !r.PathPending && epoch < 2 && r.PathEpoch == epoch && validPath(target) && target != r.RuntimePath &&
		r.ConfiguredProfileIdentity == id && r.LastAttemptID == attempt && matchesRuntime(r, id, attempt, epoch) &&
		r.State != "connected" && r.State != "captcha" && r.State != "stopping" && r.Captcha == ""
}
func (b *broker) switchPath(q request) response {
	fail := func(code string) response { return response{Error: code, State: "error"} }
	r := b.status()
	if !canSwitchPath(r, q.ExpectedProfile, q.ExpectedAttempt, q.ExpectedEpoch, q.Path) {
		return fail("CONNECTION_CHANGED")
	}
	options, err := loadConnectionOptions(b.dir)
	if err != nil || !options.AutoPaths || options.Cancelled || b.recoveryCancelled {
		return fail("CONNECTION_CHANGED")
	}
	raw, err := readSecret(filepath.Join(b.dir, "profile.dpapi"), "FreeTurn profile v1")
	if err != nil {
		return fail("PROFILE_MISSING")
	}
	if _, err = coreForPath(string(raw), q.Path, options.AdvancedCaptcha, options.ForceManualCaptcha); err != nil {
		return fail("AUTO_PATH_PROFILE_INVALID")
	}
	// Recheck health after validation and before committing the request.
	if !canSwitchPath(b.status(), q.ExpectedProfile, q.ExpectedAttempt, q.ExpectedEpoch, q.Path) {
		return fail("CONNECTION_CHANGED")
	}
	value := pathJournal{1, q.ExpectedAttempt, q.ExpectedProfile, q.ExpectedEpoch + 1, q.Path}
	encoded, _ := json.Marshal(value)
	if writeSecret(filepath.Join(b.dir, "transport-path.dpapi"), "FreeTurn transport path v1", encoded) != nil {
		return fail("CONFIG_SAVE_FAILED")
	}
	b.generation++
	b.probeConfirmed = time.Time{}
	b.probeAttempt = time.Time{}
	return response{OK: true, State: "switching", HasProfile: true, ConfiguredProfileIdentity: q.ExpectedProfile, LastAttemptID: q.ExpectedAttempt, AutoPaths: true, PathPending: true, PathEpoch: q.ExpectedEpoch, RuntimePath: r.RuntimePath}
}

func (b *broker) pathStatus(r *response, state runtimeState, options connectionOptions) bool {
	r.AutoPaths = options.AutoPaths
	r.RuntimePath = state.PathMode
	r.PathEpoch = state.PathEpoch
	r.PathPending = state.PathSwitching
	if !options.AutoPaths {
		return false
	}
	invalid := validRuntimePath(state, options) != nil
	journal, err := loadPathJournal(b.dir, options.AttemptID, options.ProfileIdentity)
	if err != nil || journal == nil && state.PathEpoch != 0 || journal != nil && journal.Epoch < state.PathEpoch {
		invalid = true
	}
	if journal != nil && journal.Epoch == state.PathEpoch && journal.Target != state.PathMode {
		invalid = true
	}
	if invalid {
		r.State = "error"
		r.Stage = "error"
		r.DiagnosticError = "PATH_STATE_INVALID"
		r.PathPending = true
		return true
	}
	if journal != nil && journal.Epoch > state.PathEpoch {
		r.PathPending = true
	}
	if b.probePathEpoch != state.PathEpoch {
		b.probePathEpoch = state.PathEpoch
		b.generation++
		b.probeConfirmed = time.Time{}
		b.probeAttempt = time.Time{}
	}
	if r.PathPending {
		r.State = "switching"
		r.Stage = "transport_start"
		return true
	}
	return false
}
