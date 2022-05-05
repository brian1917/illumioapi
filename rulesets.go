package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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
	Deleted       bool   `json:"deleted,omitempty"`
	Href          string `json:"href,omitempty"`
	Name          string `json:"name,omitempty"`
	SID           string `json:"sid,omitempty"`
	UsedByRuleSet bool   `json:"used_by_ruleset,omitempty"`
}

// IngressServices - more info to follow
type IngressServices struct {
	Port     *int    `json:"port,omitempty"`
	Protocol *int    `json:"proto,omitempty"`
	ToPort   *int    `json:"to_port,omitempty"`
	Href     *string `json:"href,omitempty"`
}

// IPTablesRules - more info to follow
type IPTablesRules struct {
	Actors      []*Actors     `json:"actors"`
	Description string        `json:"description,omitempty"`
	Enabled     bool          `json:"enabled"`
	Href        string        `json:"href"`
	IPVersion   string        `json:"ip_version"`
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

// RuleSet - more info to follow
type RuleSet struct {
	CreatedAt             string           `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy       `json:"created_by,omitempty"`
	DeletedAt             string           `json:"deleted_at,omitempty"`
	DeletedBy             *DeletedBy       `json:"deleted_by,omitempty"`
	Description           string           `json:"description,omitempty"`
	Enabled               *bool            `json:"enabled,omitempty"`
	ExternalDataReference string           `json:"external_data_reference,omitempty"`
	ExternalDataSet       string           `json:"external_data_set,omitempty"`
	Href                  string           `json:"href,omitempty"`
	IPTablesRules         []*IPTablesRules `json:"ip_tables_rules,omitempty"`
	Name                  string           `json:"name,omitempty"`
	Rules                 []*Rule          `json:"rules,omitempty"`
	Scopes                [][]*Scopes      `json:"scopes,omitempty"`
	UpdateType            string           `json:"update_type,omitempty"`
	UpdatedAt             string           `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy       `json:"updated_by,omitempty"`
}

// Rule - more info to follow
type Rule struct {
	CreatedAt                   string                         `json:"created_at,omitempty"`
	CreatedBy                   *CreatedBy                     `json:"created_by,omitempty"`
	DeletedAt                   string                         `json:"deleted_at,omitempty"`
	DeletedBy                   *DeletedBy                     `json:"deleted_by,omitempty"`
	Consumers                   []*Consumers                   `json:"consumers,omitempty"`
	ConsumingSecurityPrincipals []*ConsumingSecurityPrincipals `json:"consuming_security_principals,omitempty"`
	Description                 string                         `json:"description,omitempty"`
	Enabled                     *bool                          `json:"enabled,omitempty"`
	ExternalDataReference       string                         `json:"external_data_reference,omitempty"`
	ExternalDataSet             string                         `json:"external_data_set,omitempty"`
	Href                        string                         `json:"href,omitempty"`
	IngressServices             *[]*IngressServices            `json:"ingress_services,omitempty"`
	Providers                   []*Providers                   `json:"providers,omitempty"`
	ResolveLabelsAs             *ResolveLabelsAs               `json:"resolve_labels_as,omitempty"`
	SecConnect                  *bool                          `json:"sec_connect,omitempty"`
	Stateless                   *bool                          `json:"stateless,omitempty"`
	MachineAuth                 *bool                          `json:"machine_auth,omitempty"`
	UnscopedConsumers           *bool                          `json:"unscoped_consumers,omitempty"`
	UpdateType                  string                         `json:"update_type,omitempty"`
	UpdatedAt                   string                         `json:"updated_at,omitempty"`
	UpdatedBy                   *UpdatedBy                     `json:"updated_by,omitempty"`
}

// Scopes - more info to follow
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

// GetAllRuleSets returns a slice of Rulesets for all RuleSets in the Illumio PCE
func (p *PCE) GetAllRuleSets(provisionStatus string) ([]RuleSet, APIResponse, error) {
	return p.GetAllRuleSetsQP(nil, provisionStatus)
}

// GetAllRuleSetsQP returns a slice of Rulesets for all RuleSets in the Illumio PCE
func (p *PCE) GetAllRuleSetsQP(queryParameters map[string]string, provisionStatus string) ([]RuleSet, APIResponse, error) {
	var rulesets []RuleSet
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/rule_sets")
	if err != nil {
		return rulesets, api, fmt.Errorf("get all rulesets - %s", err)
	}

	// Set the query parameters
	for key, value := range queryParameters {
		q := apiURL.Query()
		q.Set(key, value)
		apiURL.RawQuery = q.Encode()
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

// CreateRuleSet creates a new ruleset in the Illumio PCE
func (p *PCE) CreateRuleSet(rs RuleSet) (RuleSet, APIResponse, error) {
	var newRS RuleSet
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/draft/rule_sets")
	if err != nil {
		return newRS, api, fmt.Errorf("create ruleset - %s", err)
	}

	// Call the API
	ruleSetJSON, err := json.Marshal(rs)
	if err != nil {
		return newRS, api, fmt.Errorf("create ruleset - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), *p, ruleSetJSON, false)
	api.ReqBody = string(ruleSetJSON)
	if err != nil {
		return newRS, api, fmt.Errorf("create ruleset - %s", err)
	}

	// Marshal JSON
	json.Unmarshal([]byte(api.RespBody), &newRS)

	return newRS, api, nil
}

// GetRuleSetMapName returns a map of all rulesets with the name as a key
func (p *PCE) GetRuleSetMapName(provisionStatus string) (map[string]RuleSet, APIResponse, error) {
	ruleSets, api, err := p.GetAllRuleSets(provisionStatus)
	if err != nil {
		return nil, api, fmt.Errorf("get ruleset map by name - %s", err)
	}

	rsMap := make(map[string]RuleSet)
	for _, rs := range ruleSets {
		rsMap[rs.Name] = rs
	}

	return rsMap, api, nil
}

// CreateRuleSetRule adds a rule to a RuleSet in the Illumio PCE.
//
// The provided RuleSet struct must include an Href.
func (p *PCE) CreateRuleSetRule(rulesetHref string, rule Rule) (Rule, APIResponse, error) {
	var newRule Rule
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + rulesetHref + "/sec_rules")
	if err != nil {
		return newRule, api, fmt.Errorf("create rule - %s", err)
	}

	// Call the API
	ruleJSON, err := json.Marshal(rule)
	if err != nil {
		return newRule, api, fmt.Errorf("create rule - %s", err)
	}

	api, err = apicall("POST", apiURL.String(), *p, ruleJSON, false)
	api.ReqBody = string(ruleJSON)
	if err != nil {
		return newRule, api, fmt.Errorf("create rule - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &newRule)

	return newRule, api, nil
}

// UpdateRuleSet updates an existing ruleset object in the Illumio PCE
func (p *PCE) UpdateRuleSet(ruleset RuleSet) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + ruleset.Href)
	if err != nil {
		return api, fmt.Errorf("update ruleset - %s", err)
	}

	// Remove fields that shouldn't be available for updating
	ruleset.CreatedAt = ""
	ruleset.CreatedBy = nil
	ruleset.Href = ""
	ruleset.UpdateType = ""
	ruleset.UpdatedAt = ""
	ruleset.UpdatedBy = nil
	ruleset.DeletedAt = ""
	ruleset.DeletedBy = nil
	ruleset.Rules = nil

	// Call the API
	ruleSetJSON, err := json.Marshal(ruleset)
	if err != nil {
		return api, fmt.Errorf("update ruleset - %s", err)
	}

	api.ReqBody = string(ruleSetJSON)

	api, err = apicall("PUT", apiURL.String(), *p, ruleSetJSON, false)
	if err != nil {
		return api, fmt.Errorf("update ruleset - %s", err)
	}

	return api, nil
}

// UpdateRuleSetRules updates a rule in the Illumio PCE.
//
// The provided Rule struct must include an Href.
// The method will remove properties not included in the PUT schema.
func (p *PCE) UpdateRuleSetRules(rule Rule) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + rule.Href)
	if err != nil {
		return api, fmt.Errorf("update Rule - %s", err)
	}

	// Remove fields that should be empty for the PUT schema
	rule.CreatedAt = ""
	rule.CreatedBy = nil
	rule.DeletedAt = ""
	rule.DeletedBy = nil
	rule.Href = ""
	rule.UpdatedAt = ""
	rule.UpdatedBy = nil

	// Marshal JSON
	ruleJSON, err := json.Marshal(rule)
	if err != nil {
		return api, fmt.Errorf("update rule - %s", err)
	}
	api.ReqBody = string(ruleJSON)

	// Call the API
	api, err = apicall("PUT", apiURL.String(), *p, ruleJSON, false)
	if err != nil {
		return api, fmt.Errorf("update rule - %s", err)
	}

	return api, nil
}

// GetRuleSetRuleByHref returns the rule with a specific href
func (p *PCE) GetRuleSetRuleByHref(href string) (Rule, APIResponse, error) {
	var rule Rule
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + href)
	if err != nil {
		return rule, api, fmt.Errorf("get rule - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return rule, api, fmt.Errorf("get rule - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &rule)

	return rule, api, nil
}

// GetRuleSetHrefFromRuleHref returns the href of a ruleset based on the rule's href
func (r *Rule) GetRuleSetHrefFromRuleHref() string {
	x := strings.Split(r.Href, "/")
	x = x[:len(x)-2]
	return strings.Join(x, "/")
}
