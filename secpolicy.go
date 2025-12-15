package illumioapi

import "time"

type SecPolicy struct {
	Href              string       `json:"href,omitempty"`
	CommitMessage     string       `json:"commit_message,omitempty"`
	Version           int          `json:"version,omitempty"`
	WorkloadsAffected int          `json:"workloads_affected,omitempty"`
	CreatedAt         time.Time    `json:"created_at,omitempty"`
	CreatedBy         *Href        `json:"created_by,omitempty"`
	ObjectCounts      ObjectCounts `json:"object_counts,omitempty"`
}

type ObjectCounts struct {
	RuleSets              int `json:"rule_sets,omitempty"`
	Services              int `json:"services,omitempty"`
	IPLists               int `json:"ip_lists,omitempty"`
	FirewallSettings      int `json:"firewall_settings,omitempty"`
	LabelGroups           int `json:"label_groups,omitempty"`
	SecureConnectGateways int `json:"secure_connect_gateways,omitempty"`
	VirtualServers        int `json:"virtual_servers,omitempty"`
	EnforcementBoundaries int `json:"enforcement_boundaries,omitempty"`
	VirtualServices       int `json:"virtual_services,omitempty"`
	EssentialServiceRules int `json:"essential_service_rules,omitempty"`
}

func (p *PCE) GetSecPolicy(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("sec_policy", false, queryParameters, &p.SecPolicySlice)
	if len(p.SecPolicySlice) >= 500 {
		p.SecPolicySlice = nil
		api, err = p.GetCollection("sec_policy", true, queryParameters, &p.SecPolicySlice)
	}
	return api, err
}

func (p *PCE) GetSecPolicyNeverAsync(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("sec_policy", false, queryParameters, &p.SecPolicySlice)
	return api, err
}

func (p *PCE) GetMostRecentSecPolicy() (secPolicy SecPolicy, api APIResponse, err error) {
	api, err = p.GetSecPolicyNeverAsync(nil)
	return p.SecPolicySlice[0], api, err
}
