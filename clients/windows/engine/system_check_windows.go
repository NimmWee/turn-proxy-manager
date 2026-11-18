package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"

	tun "github.com/sagernet/sing-tun"
)

type systemPolicyCheck struct {
	Policy      *systemPolicy `json:"policy"`
	Host        string        `json:"host,omitempty"`
	IP          string        `json:"ip,omitempty"`
	Port        uint16        `json:"port,omitempty"`
	Protocol    string        `json:"protocol,omitempty"`
	Application string        `json:"application,omitempty"`
}

// Pure validation/decision preview. No preflight, DNS, SYSTEM state or adapter
// lookup is required; a successful preview never means the policy is active.
func checkSystemRouting(data []byte) (map[string]any, error) {
	if len(data) > maxSystemMessage || !uniqueJSON(data) {
		return nil, errSystemRouting
	}
	var input systemPolicyCheck
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errSystemRouting
	}
	catalog, e := updatedSystemCatalog(input.PolicyCatalog())
	if e != nil {
		return nil, e
	}
	compiled, e := compileSystemPolicy(input.Policy, catalog)
	if e != nil {
		return nil, e
	}
	if input.Protocol == "" {
		input.Protocol = "tcp"
	}
	if input.Protocol != "tcp" && input.Protocol != "udp" && input.Protocol != "bittorrent" {
		return nil, errSystemRouting
	}
	if input.Port == 0 {
		input.Port = 443
	}
	var ip netip.Addr
	if input.IP != "" {
		ip, e = netip.ParseAddr(input.IP)
		if e != nil {
			return nil, errSystemRouting
		}
	}
	if input.Host != "" {
		input.Host, e = routingDomain(input.Host)
		if e != nil {
			return nil, errSystemRouting
		}
	}
	result := map[string]any{"ok": true, "policy": compiled.systemPolicy, "scope": "system-routing-preview", "active": false, "networkChanged": false, "runtimeIntegrated": tun.WithGVisor, "gvisorCompiled": tun.WithGVisor, "catalogSHA256": systemCatalogSHA256}
	result["geoIP"] = catalog.GeoIP
	if input.Policy != nil && input.Policy.Catalog != nil {
		result["catalogSHA256"] = input.Policy.Catalog.SHA256
	}
	if input.Application != "" {
		if _, e := systemAppPath(input.Application); e != nil {
			return nil, e
		}
	}
	if input.Host != "" || ip.IsValid() {
		decision := compiled.DecideFlow(input.Host, ip, input.Port, input.Protocol)
		if input.Application != "" {
			decision = compiled.applicationDecision(decision, input.Application)
		}
		result["decision"] = decision
	}
	return result, nil
}

func (q systemPolicyCheck) PolicyCatalog() *systemCatalogUpdate {
	if q.Policy == nil {
		return nil
	}
	return q.Policy.Catalog
}
