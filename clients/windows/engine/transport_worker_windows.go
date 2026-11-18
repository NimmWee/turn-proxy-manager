package main

import (
	"errors"
	"sync"
	"time"
)

func effectivePathCore(dir, raw string, options connectionOptions) (string, string, uint64, error) {
	p, err := parseProfile(raw)
	if err != nil {
		return "", "", 0, err
	}
	if p.Kind != "wireguard" {
		core, e := configureCaptcha(p.Core, options.AdvancedCaptcha, options.ForceManualCaptcha)
		return core, "", 0, e
	}
	canonical, err := canonicalPath(raw)
	if err != nil {
		return "", "", 0, err
	}
	path := options.InitialPath
	if path == "" {
		path = canonical
	}
	epoch := uint64(0)
	if options.AutoPaths {
		journal, err := loadPathJournal(dir, options.AttemptID, options.ProfileIdentity)
		if err != nil {
			return "", "", 0, err
		}
		if journal != nil {
			path = journal.Target
			epoch = journal.Epoch
		}
	}
	if options.AutoPaths || path != canonical {
		core, err := coreForPath(raw, path, options.AdvancedCaptcha, options.ForceManualCaptcha)
		return core, path, epoch, err
	}
	core, err := configureCaptcha(p.Core, options.AdvancedCaptcha, options.ForceManualCaptcha)
	return core, path, epoch, err
}

// The worker never touches WG/TUN/routes/DNS/firewall. Restart owns only the
// validated loopback FreeTurn proxy session. Caller waits before final Stop.
func startPathWorker(dir, raw string, options connectionOptions, sink *events, restart func(string) error) func() {
	if !options.AutoPaths {
		return func() {}
	}
	stop, finished := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(finished)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			journal, err := loadPathJournal(dir, options.AttemptID, options.ProfileIdentity)
			if err != nil {
				sink.OnState("error", 0, 0, "")
				sink.mu.Lock()
				sink.state.ErrorCode = "PATH_STATE_INVALID"
				sink.state.PathSwitching = true
				sink.mu.Unlock()
				continue
			}
			if journal == nil {
				continue
			}
			sink.mu.Lock()
			epoch := sink.state.PathEpoch
			sink.mu.Unlock()
			if journal.Epoch <= epoch {
				continue
			}
			latest, err := loadConnectionOptions(dir)
			if err != nil || latest.Cancelled || latest.AttemptID != options.AttemptID || latest.ProfileIdentity != options.ProfileIdentity || !latest.AutoPaths {
				return
			}
			core, err := coreForPath(raw, journal.Target, options.AdvancedCaptcha, options.ForceManualCaptcha)
			select {
			case <-stop:
				return
			default:
			}
			sink.mu.Lock()
			sink.state.PathSwitching = true
			sink.state.State = "connecting"
			sink.state.Captcha = ""
			sink.state.Manual = false
			sink.state.CaptchaID++
			sink.state.ErrorCode = ""
			sink.state.FailureStage = ""
			sink.stageLocked("transport_start")
			sink.mu.Unlock()
			if err == nil {
				err = restart(core)
			}
			sink.mu.Lock()
			sink.state.PathEpoch = journal.Epoch
			sink.state.PathMode = journal.Target
			sink.state.PathStartedAt = time.Now().Unix()
			sink.state.PathSwitching = false
			if report, e := describeEffective(raw, core); e == nil {
				sink.state.Effective = report
			} else {
				sink.state.Effective = nil
			}
			if err != nil {
				sink.state.State = "error"
				sink.state.ErrorCode = "TRANSPORT_START_FAILED"
				sink.stageLocked("error")
			}
			sink.mu.Unlock()
		}
	}()
	return func() { once.Do(func() { close(stop) }); <-finished }
}

func validRuntimePath(state runtimeState, options connectionOptions) error {
	if options.AutoPaths && (!validPath(state.PathMode) || state.PathEpoch > 2) {
		return errors.New("PATH_STATE_INVALID")
	}
	if options.AutoPaths && state.PathEpoch == 0 && state.PathMode != options.InitialPath {
		return errors.New("PATH_STATE_INVALID")
	}
	if !options.AutoPaths && state.PathEpoch != 0 {
		return errors.New("PATH_STATE_INVALID")
	}
	return nil
}
