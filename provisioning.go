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
	RuleSets              []*RuleSets              `json:"rule_sets,omitempty"`
	SecureConnectGateways []*SecureConnectGateways `json:"secure_connect_gateways,omitempty"`
	Services              []*Services              `json:"services,omitempty"`
	VirtualServers        []*VirtualServers        `json:"virtual_servers,omitempty"`
	VirtualServices       []*VirtualServices       `json:"virtual_services,omitempty"`
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

// ProvisionerHref only works with IPlists right now - needs to be updated
func ProvisionHref(pce PCE, href string) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy")
	if err != nil {
		return api, fmt.Errorf("provision href - %s", err)
	}

	// Call the API
	var provision Provision
	if strings.Contains(href, "iplist") == true {
		ipl := IPList{Href: href}
		cs := ChangeSubset{IPLists: []*IPList{&ipl}}
		provision = Provision{UpdateDescription: "Newest Office 365 IPList", ChangeSubset: &cs}
	}
	provisionJSON, err := json.Marshal(provision)
	if err != nil {
		return api, fmt.Errorf("provision href - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), pce, provisionJSON, false)
	if err != nil {
		return api, fmt.Errorf("provision href - %s", err)
	}

	return api, nil
}
