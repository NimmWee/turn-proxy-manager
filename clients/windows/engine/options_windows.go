package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/samosvalishe/free-turn-proxy/mobile"
)

type connectionOptions struct {
	AdvancedCaptcha    bool          `json:"advancedCaptcha"`
	ForceManualCaptcha bool          `json:"forceManualCaptcha,omitempty"`
	AttemptID          uint64        `json:"attemptId,omitempty"`
	Started            int64         `json:"started,omitempty"`
	SystemRouting      *systemPolicy `json:"systemRouting,omitempty"`
	FakeDNSRequired    bool          `json:"fakeDNSRequired,omitempty"`
	ProfileIdentity    string        `json:"profileIdentity,omitempty"`
	Cancelled          bool          `json:"cancelled,omitempty"`
	AutoPaths          bool          `json:"autoPaths,omitempty"`
	InitialPath        string        `json:"initialPath,omitempty"`
}

// Keep the stock upstream solver and fallback chain. Manual mode always wins,
// matching Android CoreConfigJson. The portable share URI is never extended.
func configureCaptcha(core string, advanced bool, forceManual ...bool) (string, error) {
	var config map[string]any
	if json.Unmarshal([]byte(core), &config) != nil {
		return "", errProfile
	}
	vk, ok := config["vk"].(map[string]any)
	if !ok {
		return "", errProfile
	}
	manual, _ := vk["manualCaptcha"].(bool)
	if len(forceManual) > 0 && forceManual[0] && config["provider"] != "direct" {
		manual = true
		vk["manualCaptcha"] = true
		vk["autoCaptcha"] = false
	}
	vk["advancedCaptcha"] = advanced && !manual && config["provider"] != "direct"
	data, e := json.Marshal(config)
	if e != nil || mobile.ValidateConfig(string(data)) != "" {
		return "", errProfile
	}
	return string(data), nil
}

func loadConnectionOptions(dir string) (connectionOptions, error) {
	var options connectionOptions
	data, e := readSecret(filepath.Join(dir, "options.dpapi"), "FreeTurn connection options v1")
	if os.IsNotExist(e) {
		return options, nil
	}
	if e != nil {
		return options, e
	}
	return decodeConnectionOptions(data)
}

func decodeConnectionOptions(data []byte) (connectionOptions, error) {
	var options connectionOptions
	if len(data) > maxSystemMessage || !uniqueJSON(data) {
		return options, errProfile
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&options) != nil || d.Decode(new(any)) != io.EOF {
		return options, errProfile
	}
	if options.ProfileIdentity != "" && !validProfileIdentity(options.ProfileIdentity) {
		return options, errProfile
	}
	if options.InitialPath != "" && !validPath(options.InitialPath) || options.AutoPaths && options.InitialPath != "direct" {
		return options, errProfile
	}
	if options.SystemRouting != nil {
		catalog, e := loadSystemCatalog()
		if e != nil {
			return options, e
		}
		compiled, e := compileSystemPolicy(options.SystemRouting, catalog)
		if e != nil {
			return options, e
		}
		options.SystemRouting = compiled.systemPolicy
	}
	return options, nil
}
