package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/services"
	"testing"
)

func TestSCMFailuresSurviveNilDispatcherError(t *testing.T) {
	for _, s := range []svc.Status{{State: svc.Stopped}, {State: svc.Stopped, Win32ExitCode: 1077}, {State: svc.Running, Win32ExitCode: 1066, ServiceSpecificExitCode: 2}} {
		if code, _ := serviceExitDiagnostic(s); code != "" {
			t.Fatal("normal/never-started/running service reported as failed")
		}
	}
	for _, test := range []struct {
		status      svc.Status
		code, stage string
	}{
		{svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), ServiceSpecificExitCode: uint32(services.ErrorLoadConfiguration)}, "WG_CONFIG_FAILED", "profile_check"},
		{svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR), ServiceSpecificExitCode: uint32(services.ErrorCreateNetworkAdapter)}, "WG_ADAPTER_FAILED", "wireguard_start"},
		{svc.Status{State: svc.Stopped, Win32ExitCode: uint32(windows.ERROR_SERVICE_REQUEST_TIMEOUT)}, "SCM_START_TIMEOUT", "service_start"},
	} {
		code, stage := serviceExitDiagnostic(test.status)
		if code != test.code || stage != test.stage {
			t.Fatal("SCM error lost or misclassified despite nil svc.Run error")
		}
	}
}
