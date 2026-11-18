package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestSystemStatusRequiresWGAndFreshVPNEgress(t *testing.T) {
	now := time.Unix(2000, 0)
	for _, tc := range []struct {
		active, handshake bool
		egress            int64
		want              string
	}{
		{false, false, 0, "starting"}, {true, false, 1999, "tunnel_unverified"}, {true, true, 0, "handshake"}, {true, true, 1969, "handshake"}, {true, true, 2001, "handshake"}, {true, true, 1999, "connected"},
	} {
		state := runtimeState{State: "connected", SystemRouting: &systemRuntimeReport{Requested: true, Active: tc.active, Handshake: tc.handshake, EgressAt: tc.egress, DirectFlows: 10000, Rx: 42}}
		r := response{}
		if !applySystemRoutingStatus(&r, state, true, now) || r.State != tc.want || r.Rx != 42 {
			t.Fatalf("unsafe routing status: %s, want %s", r.State, tc.want)
		}
	}
	r := response{Captcha: "local challenge"}
	if !applySystemRoutingStatus(&r, runtimeState{State: "connected", SystemRouting: &systemRuntimeReport{Requested: true, Active: true, Handshake: true, EgressAt: 1999}}, true, now) || r.State != "captcha" {
		t.Fatal("health hid CAPTCHA")
	}
	if applySystemRoutingStatus(&response{}, runtimeState{}, true, now) {
		t.Fatal("default WGNT status intercepted")
	}
}

func TestSystemServiceStopWaitsForStartupRollback(t *testing.T) {
	begun := make(chan struct{})
	cancelled := make(chan struct{})
	release := make(chan struct{})
	s := &systemTunnelService{sink: &events{}, start: func(ctx context.Context) (*systemRuntime, error) {
		close(begun)
		<-ctx.Done()
		close(cancelled)
		<-release
		return nil, errors.New("SYSTEM_ROUTING_CANCELLED")
	}}
	requests := make(chan svc.ChangeRequest, 1)
	statuses := make(chan svc.Status, 16)
	done := make(chan bool, 1)
	go func() { specific, code := s.Execute(nil, requests, statuses); done <- !specific && code == 0 }()
	select {
	case <-begun:
	case <-time.After(time.Second):
		t.Fatal("startup did not begin")
	}
	first, second := <-statuses, <-statuses
	if first.State != svc.StartPending || second.State != svc.Running || second.Accepts&svc.AcceptStop == 0 {
		t.Fatal("async network startup did not become controllable by SCM")
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("SCM Stop did not cancel startup")
	}
	select {
	case <-done:
		t.Fatal("service exited before startup rollback completed")
	default:
	}
	close(release)
	select {
	case ok := <-done:
		if !ok || s.result != nil {
			t.Fatal("intentional cancel recorded as connection failure")
		}
	case <-time.After(time.Second):
		t.Fatal("service did not finish rollback")
	}
}
