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
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/label_groups")
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

// CreateLabelGroup creates a new Label Group in the Illumio PCE.
//
// The function will remove properties not in the POST schema
func (p *PCE) CreateLabelGroup(labelGroup LabelGroup) (LabelGroup, APIResponse, error) {
	var newLabelGroup LabelGroup
	var api APIResponse
	var err error

	// Sanitize the Label Group
	labelGroup.Href = ""
	labelGroup.Usage = nil

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/draft/label_groups")
	if err != nil {
		return newLabelGroup, api, fmt.Errorf("create label group - %s", err)
	}

	// Call the API
	labelGroupJSON, err := json.Marshal(labelGroup)
	if err != nil {
		return newLabelGroup, api, fmt.Errorf("create label group - %s", err)
	}
	api.ReqBody = string(labelGroupJSON)
	api, err = apicall("POST", apiURL.String(), *p, labelGroupJSON, false)
	if err != nil {
		return newLabelGroup, api, fmt.Errorf("create label group - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &newLabelGroup)

	return newLabelGroup, api, nil
}

// UpdateLabelGroup updates an existing Label Group in the Illumio PCE.
//
// The provided Label Group struct must include an Href.
// The function will remove properties not included in the PUT schema.
func (p *PCE) UpdateLabelGroup(labelGroup LabelGroup) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + labelGroup.Href)
	if err != nil {
		return api, fmt.Errorf("update label group - %s", err)
	}

	// Remove fields that should be empty for the PUT schema
	labelGroup.Href = ""
	labelGroup.Usage = nil
	labelGroup.Key = ""

	// Marshal JSON
	labelGroupJSON, err := json.Marshal(labelGroup)
	if err != nil {
		return api, fmt.Errorf("update label group - %s", err)
	}
	api.ReqBody = string(labelGroupJSON)

	// Call the API
	api, err = apicall("PUT", apiURL.String(), *p, labelGroupJSON, false)
	if err != nil {
		return api, fmt.Errorf("update label group - %s", err)
	}

	return api, nil
}

// ExpandLabelGroup returns a string of label hrefs in a label group
// Every subgroup (and nested subgroup) is expanded
func (p *PCE) ExpandLabelGroup(href string) (labelHrefs []string) {

	// Get the labels from the original label group
	a, _ := p.expandLabelGroup(href)
	labelHrefs = append(labelHrefs, a...)

	// Iterate through the subgroups of the original label group
	for _, sg := range p.LabelGroups[href].SubGroups {
		// Get the labels in that subgroup and the additional subgroups
		l, moreSGs := p.expandLabelGroup(sg.Href)
		// Append the labels
		labelHrefs = append(labelHrefs, l...)
		// While there are more subgroups, continue expanding them
		for len(moreSGs) > 0 {
			for _, newSG := range moreSGs {
				l, moreSGs = p.expandLabelGroup(newSG)
				// Append the labels
				labelHrefs = append(labelHrefs, l...)
			}
		}
	}

	// De-dupe and return
	labelGroupMap := make(map[string]bool)
	for _, l := range labelHrefs {
		labelGroupMap[l] = true
	}
	labelHrefs = []string{}
	for l := range labelGroupMap {
		labelHrefs = append(labelHrefs, l)
	}
	return labelHrefs
}

func (p *PCE) expandLabelGroup(href string) (labelHrefs []string, moreSGs []string) {
	for _, l := range p.LabelGroups[href].Labels {
		labelHrefs = append(labelHrefs, l.Href)
	}
	for _, sg := range p.LabelGroups[href].SubGroups {
		moreSGs = append(moreSGs, sg.Href)
	}
	return labelHrefs, moreSGs
}
