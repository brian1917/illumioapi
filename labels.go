package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// A Label represents an Illumio Label.
type Label struct {
	CreatedAt             string     `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy `json:"created_by,omitempty"`
	Deleted               bool       `json:"deleted,omitempty"`
	ExternalDataReference string     `json:"external_data_reference,omitempty"`
	ExternalDataSet       string     `json:"external_data_set,omitempty"`
	Href                  string     `json:"href,omitempty"`
	Key                   string     `json:"key,omitempty"`
	UpdatedAt             string     `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy `json:"updated_by,omitempty"`
	Value                 string     `json:"value,omitempty"`
}

// CreatedBy represents the CreatedBy property of an object
type CreatedBy struct {
	Href string `json:"href"`
}

// UpdatedBy represents the UpdatedBy property of an object
type UpdatedBy struct {
	Href string `json:"href"`
}

// GetAllLabels returns a slice of all Labels in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
func (p *PCE) GetAllLabels() ([]Label, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/labels")
	if err != nil {
		return nil, APIResponse{}, fmt.Errorf("get all labels - %s", err)
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all workloads - %s", err)
	}

	// Unmarshal response to struct
	var labels []Label
	json.Unmarshal([]byte(api.RespBody), &labels)

	// If length is 500, re-run with async
	if len(labels) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all workloads - %s", err)
		}

		// Unmarshal response to struct
		var asyncLabels []Label
		json.Unmarshal([]byte(api.RespBody), &asyncLabels)

		return asyncLabels, api, nil
	}

	// Return if less than 500
	return labels, api, nil
}

// GetLabelbyKeyValue finds a label based on the key and value.
// It will only return one Label that is an exact match.
func (p *PCE) GetLabelbyKeyValue(key, value string) (Label, APIResponse, error) {
	var l Label
	var labels []Label
	var api APIResponse

	// Build the API URL and Query Parameters
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/labels")
	if err != nil {
		return l, api, fmt.Errorf("get label - %s", err)
	}
	q := apiURL.Query()
	q.Set("key", key)
	q.Set("value", value)
	apiURL.RawQuery = q.Encode()

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return l, api, fmt.Errorf("get label - %s", err)
	}

	// Unmarshal respones to struct
	json.Unmarshal([]byte(api.RespBody), &labels)

	//Illumio API returns any label that contains the search team. We need exact
	for _, label := range labels {
		if label.Value == value {
			return label, api, nil
		}
	}

	// If we reach here, a label doesn't exist - return an emtpy label struct and no error
	return l, api, nil
}

// GetLabelbyHref returns a label based on the provided HREF.
func (p *PCE) GetLabelbyHref(href string) (Label, APIResponse, error) {
	var l Label
	var api APIResponse

	// Build the API URL and Query Parameters
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/" + href)
	if err != nil {
		return l, api, fmt.Errorf("get label by href - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return l, api, fmt.Errorf("get label by href- %s", err)
	}

	// Unmarshal respones to struct
	json.Unmarshal([]byte(api.RespBody), &l)

	// If we reach here, a label doesn't exist - return an emtpy label struct and no error
	return l, api, nil
}

// CreateLabel creates a new Label in the Illumio PCE.
func (p *PCE) CreateLabel(label Label) (Label, APIResponse, error) {
	var newLabel Label
	var api APIResponse
	var err error

	// Check to make sure the label key is valid
	label.Key = strings.ToLower(label.Key)
	if label.Key != "app" && label.Key != "env" && label.Key != "role" && label.Key != "loc" {
		return newLabel, api, errors.New("label key is not app, env, role, or loc")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/labels")
	if err != nil {
		return newLabel, api, fmt.Errorf("create label - %s", err)
	}

	// Create payload
	labelJSON, err := json.Marshal(label)
	if err != nil {
		return newLabel, api, fmt.Errorf("create label - %s", err)
	}
	api.ReqBody = string(labelJSON)

	// Call the API
	api, err = apicall("POST", apiURL.String(), *p, labelJSON, false)
	if err != nil {
		return newLabel, api, fmt.Errorf("create label - %s", err)
	}

	// Unmarshal new label
	json.Unmarshal([]byte(api.RespBody), &newLabel)

	return newLabel, api, nil
}

// UpdateLabel updates an existing label in the Illumio PCE.
// The provided label struct must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateLabel(label Label) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + label.Href)
	if err != nil {
		return api, fmt.Errorf("update label - %s", err)
	}

	// Create a new label with just the fields that should be updated
	l := Label{Value: label.Value, ExternalDataReference: label.ExternalDataReference, ExternalDataSet: label.ExternalDataSet}

	// Call the API
	labelJSON, err := json.Marshal(l)
	if err != nil {
		return api, fmt.Errorf("update label - %s", err)
	}
	api.ReqBody = string(labelJSON)

	api, err = apicall("PUT", apiURL.String(), *p, labelJSON, false)
	if err != nil {
		return api, fmt.Errorf("update label - %s", err)
	}

	return api, nil
}

// LabelsToRuleStructure takes a slice of labels and returns a slice of slices for how the labels would be organized as read by the PCE rule processing.
// For example {"A-ERP", "A-CRM", "E-PROD"} will return [{"A-ERP, E-PROD"}. {"A-CRM", "E-PROD"}]
func LabelsToRuleStructure(labels []Label) ([][]Label, error) {

	// Create 4 slices: roleLabels, appLabels, envLabels, locLabels and put each label in the correct one
	var roleLabels, appLabels, envLabels, locLabels []Label
	for _, l := range labels {
		switch l.Key {
		case "role":
			roleLabels = append(roleLabels, l)
		case "app":
			appLabels = append(appLabels, l)
		case "env":
			envLabels = append(envLabels, l)
		case "loc":
			locLabels = append(locLabels, l)
		default:
			return nil, errors.New("label key is not role, app, env, or loc")
		}
	}

	// If any of the label slices are empty, put a filler that we will ignore in with blank key and value
	targets := []*[]Label{&roleLabels, &appLabels, &envLabels, &locLabels}
	for _, t := range targets {
		if len(*t) == 0 {
			*t = append(*t, Label{Key: "", Value: ""})
		}
	}

	// Produce an array for every combination that is needed.
	var results [][]Label
	for _, r := range roleLabels {
		for _, a := range appLabels {
			for _, e := range envLabels {
				for _, l := range locLabels {
					n := []Label{}
					if r.Value != "" {
						n = append(n, r)
					}
					if a.Value != "" {
						n = append(n, a)
					}
					if e.Value != "" {
						n = append(n, e)
					}
					if l.Value != "" {
						n = append(n, l)
					}
					results = append(results, n)
				}
			}
		}
	}

	return results, nil

}
