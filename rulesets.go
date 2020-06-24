package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Actors - more info to follow
type Actors struct {
	Actors     string      `json:"actors,omitempty"`
	Label      *Label      `json:"label,omitempty"`
	LabelGroup *LabelGroup `json:"label_group,omitempty"`
	Workload   *Workload   `json:"workload,omitempty"`
}

// Consumers - more info to follow
type Consumers struct {
	Actors         string          `json:"actors,omitempty"`
	IPList         *IPList         `json:"ip_list,omitempty"`
	Label          *Label          `json:"label,omitempty"`
	LabelGroup     *LabelGroup     `json:"label_group,omitempty"`
	VirtualService *VirtualService `json:"virtual_service,omitempty"`
	Workload       *Workload       `json:"workload,omitempty"`
}

// ConsumingSecurityPrincipals - more info to follow
type ConsumingSecurityPrincipals struct {
	Actors      []*Actors     `json:"actors"`
	Description string        `json:"description,omitempty"`
	Enabled     bool          `json:"enabled"`
	Href        string        `json:"href"`
	IPVersion   string        `json:"ip_version"`
	Statements  []*Statements `json:"statements"`
}

// IngressServices - more info to follow
type IngressServices struct {
}

// IpTablesRules - more info to follow
type IPTablesRules struct {
	Actors      []*Actors     `json:"actors"`
	Description string        `json:"description,omitempty"`
	Enabled     bool          `json:"enabled"`
	Href        string        `json:"href"`
	IpVersion   string        `json:"ip_version"`
	Statements  []*Statements `json:"statements"`
}

// Providers - more info to follow
type Providers struct {
	Actors         string          `json:"actors,omitempty"`
	IPList         *IPList         `json:"ip_list,omitempty"`
	Label          *Label          `json:"label,omitempty"`
	LabelGroup     *LabelGroup     `json:"label_group,omitempty"`
	VirtualServer  *VirtualServer  `json:"virtual_server,omitempty"`
	VirtualService *VirtualService `json:"virtual_service,omitempty"`
	Workload       *Workload       `json:"workload,omitempty"`
}

// ResolveLabelsAs - more info to follow
type ResolveLabelsAs struct {
	Consumers []string `json:"consumers"`
	Providers []string `json:"providers"`
}

// Ruleset - more info to follow
type RuleSet struct {
	CreatedAt             string           `json:"created_at"`
	CreatedBy             *CreatedBy       `json:"created_by,omitempty"`
	DeletedAt             string           `json:"deleted_at"`
	DeletedBy             *DeletedBy       `json:"deleted_by,omitempty"`
	Description           string           `json:"description"`
	Enabled               bool             `json:"enabled"`
	ExternalDataReference interface{}      `json:"external_data_reference,omitempty"`
	ExternalDataSet       interface{}      `json:"external_data_set,omitempty"`
	Href                  string           `json:"href,omitempty"`
	IPTablesRules         []*IPTablesRules `json:"ip_tables_rules,omitempty"`
	Name                  string           `json:"name"`
	Rules                 []*Rule          `json:"rules"`
	Scopes                [][]*Scopes      `json:"scopes"`
	UpdateType            string           `json:"update_type,omitempty"`
	UpdatedAt             string           `json:"updated_at"`
	UpdatedBy             *UpdatedBy       `json:"updated_by,omitempty"`
}

// Rules - more info to follow
type Rule struct {
	Consumers                   []*Consumers                 `json:"consumers"`
	ConsumingSecurityPrincipals *ConsumingSecurityPrincipals `json:"consuming_security_principals,omitempty"`
	Description                 string                       `json:"description,omitempty"`
	Enabled                     bool                         `json:"enabled"`
	ExternalDataReference       interface{}                  `json:"external_data_reference,omitempty"`
	ExternalDataSet             interface{}                  `json:"external_data_set,omitempty"`
	Href                        string                       `json:"href,omitempty"`
	IngressServices             []*IngressServices           `json:"ingress_services"`
	Providers                   []*Providers                 `json:"providers"`
	ResolveLabelsAs             *ResolveLabelsAs             `json:"resolve_labels_as"`
	SecConnect                  bool                         `json:"sec_connect,omitempty"`
	UnscopedConsumers           bool                         `json:"unscoped_consumers,omitempty"`
	UpdateType                  string                       `json:"update_type,omitempty"`
}

// Scope - more info to follow
type Scopes struct {
	Label      *Label      `json:"label,omitempty"`
	LabelGroup *LabelGroup `json:"label_group,omitempty"`
}

// Statements are part of a custom IPTables rule
type Statements struct {
	ChainName  string `json:"chain_name"`
	Parameters string `json:"parameters"`
	TableName  string `json:"table_name"`
}

// VirtualServer represents a Virtual Server in the Illumio PCE
type VirtualServer struct {
	Href string `json:"href"`
}

// GetAllRuleSets returns a slice of Rulesets for all RuleSets in the Illumio PCE
func (p *PCE) GetAllRuleSets(provisionStatus string) ([]RuleSet, APIResponse, error) {
	var rulesets []RuleSet
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/rule_sets")
	if err != nil {
		return rulesets, api, fmt.Errorf("get all rulesets - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return rulesets, api, fmt.Errorf("get all rulesets - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &rulesets)

	// If length is 500, re-run with async
	if len(rulesets) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return rulesets, api, fmt.Errorf("get all rulesets - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &rulesets)
	}

	return rulesets, api, nil
}
