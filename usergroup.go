package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// ADUserGroup represents an AD group used as policy oject in the PCE
type ADUserGroup struct {
	Href          string `json:"href,omitempty"`
	Deleted       bool   `json:"deleted,omitempty"`
	UsedByRuleSet bool   `json:"used_by_ruleset,omitempty"`
	Name          string `json:"name,omitempty"`
	Sid           string `json:"sid,omitempty"`
	Description   string `json:"description,omitempty"`
}

// CreateADUserGroup creates a user group policy object in the PCE
func (p *PCE) CreateADUserGroup(g ADUserGroup) (ADUserGroup, APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/security_principals")
	if err != nil {
		return ADUserGroup{}, api, fmt.Errorf("CreateADUserGroup - %s", err)
	}

	// Create payload
	userGroupJSON, err := json.Marshal(g)
	if err != nil {
		return ADUserGroup{}, api, fmt.Errorf("CreateADUserGroup - %s", err)
	}

	// Call the API
	api, err = apicall("POST", apiURL.String(), *p, userGroupJSON, false)
	if err != nil {
		return ADUserGroup{}, api, fmt.Errorf("CreateADUserGroup - %s", err)
	}

	// Unmarshal new label
	var newGroup ADUserGroup
	json.Unmarshal([]byte(api.RespBody), &newGroup)

	return newGroup, api, nil
}
