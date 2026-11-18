package main

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/services"
)

// svc.Run returns dispatcher errors, not the Execute callback's exit code.
// Read the actual SCM result separately; 1077 explicitly means never started.
func serviceExitDiagnostic(status svc.Status) (code, stage string) {
	if status.State != svc.Stopped || status.Win32ExitCode == 0 || status.Win32ExitCode == 1077 {
		return "", ""
	}
	if status.Win32ExitCode == uint32(windows.ERROR_SERVICE_REQUEST_TIMEOUT) {
		return "SCM_START_TIMEOUT", "service_start"
	}
	if status.Win32ExitCode != uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR) {
		return "WINDOWS_SERVICE_FAILED", "wireguard_start"
	}
	switch services.Error(status.ServiceSpecificExitCode) {
	case services.ErrorLoadConfiguration:
		return "WG_CONFIG_FAILED", "profile_check"
	case services.ErrorRingloggerOpen:
		return "WG_LOG_FAILED", "wireguard_start"
	case services.ErrorCreateNetworkAdapter:
		return "WG_ADAPTER_FAILED", "wireguard_start"
	case services.ErrorFirewall:
		return "WG_FIREWALL_FAILED", "wireguard_start"
	case services.ErrorDeviceSetConfig, services.ErrorDeviceBringUp:
		return "WG_DRIVER_FAILED", "wireguard_start"
	case services.ErrorSetNetConfig, services.ErrorBindSocketsToDefaultRoutes, services.ErrorMonitorMTUChanges:
		return "WG_NETWORK_CONFIG_FAILED", "wireguard_start"
	case services.ErrorDNSLookup:
		return "DNS_FAILED", "wireguard_start"
	default:
		return "WINDOWS_SERVICE_FAILED", "wireguard_start"
	}
}
