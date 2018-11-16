package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Actors represent Actors
type Actors struct {
	Actors     string      `json:"actors,omitempty"`
	Label      *Label      `json:"label,omitempty"`
	LabelGroup *LabelGroup `json:"label_group,omitempty"`
	Workload   *Workload   `json:"workload,omitempty"`
}

// Consumers represent a consumer in an Illumio rule
type Consumers struct {
	Actors       string        `json:"actors,omitempty"`
	BoundService *BoundService `json:"bound_service,omitempty"`
	IPList       *IPList       `json:"ip_list,omitempty"`
	Label        *Label        `json:"label,omitempty"`
	LabelGroup   *LabelGroup   `json:"label_group,omitempty"`
	Workload     *Workload     `json:"workload,omitempty"`
}

// ConsumingSecurityPrincipals represent Consuming Security Principals
type ConsumingSecurityPrincipals struct {
	Href string `json:"href,omitempty"`
}

// IPTablesRules represent IP Table Rules
type IPTablesRules struct {
	Actors      []*Actors     `json:"actors"`
	Description string        `json:"description,omitempty"`
	Enabled     bool          `json:"enabled"`
	Href        string        `json:"href"`
	IPVersion   string        `json:"ip_version"`
	Statements  []*Statements `json:"statements"`
}

// Providers represent providers in an Illumio ruleset
type Providers struct {
	Actors        string         `json:"actors,omitempty"`
	BoundService  *BoundService  `json:"bound_service,omitempty"`
	IPList        *IPList        `json:"ip_list,omitempty"`
	Label         *Label         `json:"label,omitempty"`
	LabelGroup    *LabelGroup    `json:"label_group,omitempty"`
	VirtualServer *VirtualServer `json:"virtual_server,omitempty"`
	Workload      *Workload      `json:"workload,omitempty"`
}

// Ruleset represents an Illumio RuleSet
type Ruleset struct {
	CreatedAt             string           `json:"created_at"`
	CreatedBy             *CreatedBy       `json:"created_by,omitempty"`
	DeletedAt             string           `json:"deleted_at"`
	DeletedBy             *DeletedBy       `json:"deleted_by,omitempty"`
	Description           string           `json:"description"`
	Enabled               bool             `json:"enabled"`
	ExternalDataReference string           `json:"external_data_reference,omitempty"`
	ExternalDataSet       string           `json:"external_data_set,omitempty"`
	Href                  string           `json:"href,omitempty"`
	IPTablesRules         []*IPTablesRules `json:"ip_tables_rules,omitempty"`
	Name                  string           `json:"name"`
	Rules                 []*Rules         `json:"rules"`
	Scopes                [][]*Scopes      `json:"scopes"`
	UpdateType            string           `json:"update_type,omitempty"`
	UpdatedAt             string           `json:"updated_at"`
	UpdatedBy             *UpdatedBy       `json:"updated_by,omitempty"`
	PolicySecStatus       string
}

// Rules represent Illumio Rules
type Rules struct {
	Consumers                   []*Consumers                   `json:"consumers"`
	ConsumingSecurityPrincipals []*ConsumingSecurityPrincipals `json:"consuming_security_principals,omitempty"`
	Description                 string                         `json:"description,omitempty"`
	Enabled                     bool                           `json:"enabled"`
	ExternalDataReference       interface{}                    `json:"external_data_reference,omitempty"`
	ExternalDataSet             interface{}                    `json:"external_data_set,omitempty"`
	Href                        string                         `json:"href,omitempty"`
	Providers                   []*Providers                   `json:"providers"`
	SecConnect                  bool                           `json:"sec_connect,omitempty"`
	Service                     *Service                       `json:"service"`
	UnscopedConsumers           bool                           `json:"unscoped_consumers,omitempty"`
	UpdateType                  string                         `json:"update_type,omitempty"`
}

// Scopes represent the scope of an Illumio Rule
type Scopes struct {
	Label      *Label      `json:"label,omitempty"`
	LabelGroup *LabelGroup `json:"label_group,omitempty"`
}

// Statements represent statements
type Statements struct {
	ChainName  string `json:"chain_name"`
	Parameters string `json:"parameters"`
	TableName  string `json:"table_name"`
}

// VirtualServer represent Virtual Servers
type VirtualServer struct {
	Href string `json:"href"`
}

// GetAllRuleSets returns a slice of Rulesets for all RuleSets in the Illumio PCE
func GetAllRuleSets(pce PCE, provisionStatus string) ([]Ruleset, APIResponse, error) {
	var rulesets []Ruleset
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/" + provisionStatus + "/rule_sets")
	if err != nil {
		return rulesets, api, fmt.Errorf("get all rulesets - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return rulesets, api, fmt.Errorf("get all rulesets - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &rulesets)

	// If length is 500, re-run with async
	if len(rulesets) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return rulesets, api, fmt.Errorf("get all rulesets - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &rulesets)
	}

	return rulesets, api, nil
}
