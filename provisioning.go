package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ChangeSubset Hash of pending hrefs, organized by model
type ChangeSubset struct {
	FirewallSettings      []*FirewallSettings      `json:"firewall_settings,omitempty"`
	IPLists               []*IPList                `json:"ip_lists,omitempty"`
	LabelGroups           []*LabelGroup            `json:"label_groups,omitempty"`
	RuleSets              []*RuleSet               `json:"rule_sets,omitempty"`
	SecureConnectGateways []*SecureConnectGateways `json:"secure_connect_gateways,omitempty"`
	Services              []*Service               `json:"services,omitempty"`
	VirtualServers        []*VirtualServer         `json:"virtual_servers,omitempty"`
	VirtualServices       []*VirtualService        `json:"virtual_services,omitempty"`
}

// FirewallSettings
type FirewallSettings struct {
	Href string `json:"href"`
}

// Provision
type Provision struct {
	ChangeSubset      *ChangeSubset `json:"change_subset,omitempty"`
	UpdateDescription string        `json:"update_description,omitempty"`
}

// RuleSets
type RuleSets struct {
	Href string `json:"href"`
}

// SecureConnectGateways
type SecureConnectGateways struct {
	Href string `json:"href"`
}

// VirtualServers
type VirtualServers struct {
	Href string `json:"href"`
}

// VirtualServices
type VirtualServices struct {
	Href string `json:"href"`
}

// ProvisionCS provisions a ChangeSubset
func (p *PCE) ProvisionCS(cs ChangeSubset, comment string) (APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy")
	if err != nil {
		return APIResponse{}, fmt.Errorf("provision href - %s", err)
	}

	// Build the Provision
	provision := Provision{ChangeSubset: &cs, UpdateDescription: comment}
	provisionJSON, err := json.Marshal(provision)
	if err != nil {
		return APIResponse{}, err
	}
	api, err := apicall("POST", apiURL.String(), *p, provisionJSON, false)
	if err != nil {
		return api, err
	}

	return api, nil
}

// ProvisionHref provisions a slice of HREFs
func (p *PCE) ProvisionHref(hrefs []string, comment string) (APIResponse, error) {

	// Build our variables
	var ipl []*IPList
	var services []*Service
	var ruleSets []*RuleSet
	var labelGroups []*LabelGroup
	var virtualServices []*VirtualService
	var virtualServers []*VirtualServer
	var fs []*FirewallSettings
	var secureConnectGateways []*SecureConnectGateways

	// Process our list of HREFs
	for _, h := range hrefs {

		if strings.Contains(h, "/ip_lists/") {
			ipl = append(ipl, &IPList{Href: h})
		}
		// Services
		if strings.Contains(h, "/services/") {
			services = append(services, &Service{Href: h})
		}
		// Rule Sets
		if strings.Contains(h, "/rule_sets/") {
			ruleSets = append(ruleSets, &RuleSet{Href: h})
		}
		// Label Groups
		if strings.Contains(h, "/label_groups/") {
			labelGroups = append(labelGroups, &LabelGroup{Href: h})
		}
		// Virtual Services
		if strings.Contains(h, "/virtual_services/") {
			virtualServices = append(virtualServices, &VirtualService{Href: h})
		}
		// Virtual Servers
		if strings.Contains(h, "/virtual_servers/") {
			virtualServers = append(virtualServers, &VirtualServer{Href: h})
		}
		// Firewall Settings
		if strings.Contains(h, "/firewall_settings/") {
			fs = append(fs, &FirewallSettings{Href: h})
		}
		// SecureConnect Gateway
		if strings.Contains(h, "/secure_connect_gateways/") {
			secureConnectGateways = append(secureConnectGateways, &SecureConnectGateways{Href: h})
		}

	}
	// Build the Provision
	api, err := p.ProvisionCS(ChangeSubset{
		FirewallSettings:      fs,
		IPLists:               ipl,
		LabelGroups:           labelGroups,
		RuleSets:              ruleSets,
		SecureConnectGateways: secureConnectGateways,
		Services:              services,
		VirtualServers:        virtualServers,
		VirtualServices:       virtualServices,
	}, comment)
	if err != nil {
		return api, err
	}

	return api, nil
}

// GetAllPending gets all the items pending provisioning
func (p *PCE) GetAllPending() (ChangeSubset, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/pending")
	if err != nil {
		return ChangeSubset{}, APIResponse{}, err
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return ChangeSubset{}, api, err
	}

	// Unmarshal response to struct
	var cs ChangeSubset
	json.Unmarshal([]byte(api.RespBody), &cs)

	// Return
	return cs, api, nil
}
