package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// LabelGroup represents a Label Group in the Illumio PCE
type LabelGroup struct {
	Description           string       `json:"description,omitempty"`
	ExternalDataReference string       `json:"external_data_reference,omitempty"`
	ExternalDataSet       string       `json:"external_data_set,omitempty"`
	Href                  string       `json:"href,omitempty"`
	Key                   string       `json:"key,omitempty"`
	Labels                []*Label     `json:"labels,omitempty"`
	Name                  string       `json:"name,omitempty"`
	SubGroups             []*SubGroups `json:"sub_groups,omitempty"`
	Usage                 *Usage       `json:"usage,omitempty"`
}

// SubGroups represent SubGroups for Label Groups
type SubGroups struct {
	Href string `json:"href"`
	Name string `json:"name,omitempty"`
}

// Usage covers how a LabelGroup is used in the PCE
type Usage struct {
	LabelGroup         bool `json:"label_group"`
	Rule               bool `json:"rule"`
	Ruleset            bool `json:"ruleset"`
	StaticPolicyScopes bool `json:"static_policy_scopes,omitempty"`
}

// GetAllLabelGroups returns a slice of all Label Groups of a
// specific provision status in the Illumio PCE.
//
// The pvoision status must be "draft" or "active".
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func (p *PCE) GetAllLabelGroups(provisionStatus string) ([]LabelGroup, APIResponse, error) {

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return nil, APIResponse{}, errors.New("get all label groups - provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v1/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/label_groups")
	if err != nil {
		return nil, APIResponse{}, fmt.Errorf("get all label groups - %s", err)
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all label groups - %s", err)
	}

	var labelGroups []LabelGroup
	json.Unmarshal([]byte(api.RespBody), &labelGroups)

	// If length is 500, re-run with async
	if len(labelGroups) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all label groups - %s", err)
		}

		// Unmarshal response to struct
		var asyncLabelGroups []LabelGroup
		json.Unmarshal([]byte(api.RespBody), &asyncLabelGroups)

		return asyncLabelGroups, api, nil
	}

	// Return if less than 500
	return labelGroups, api, nil
}
