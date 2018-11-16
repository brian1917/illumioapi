package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// A Label is a Label policy object in the Illumio PCE
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
//
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func GetAllLabels(pce PCE) ([]Label, APIResponse, error) {
	var labels []Label
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/labels")
	if err != nil {
		return labels, api, fmt.Errorf("get all labels - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return labels, api, fmt.Errorf("get all workloads - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &labels)

	// If length is 500, re-run with async
	if len(labels) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return labels, api, fmt.Errorf("get all workloads - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &labels)
	}

	return labels, api, nil
}

// GetLabel finds a specific Label based on the key and value.
//
// Will only return one Label that is an exact match.
func GetLabel(pce PCE, key, value string) (Label, APIResponse, error) {
	var l Label
	var labels []Label
	var api APIResponse

	// Build the API URL and Query Parameters
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/labels")
	if err != nil {
		return l, api, fmt.Errorf("get label - %s", err)
	}
	q := apiURL.Query()
	q.Set("key", key)
	q.Set("value", value)
	apiURL.RawQuery = q.Encode()

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
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

// CreateLabel creates a new Label in the Illumio PCE.
func CreateLabel(pce PCE, label Label) (Label, APIResponse, error) {
	var newLabel Label
	var api APIResponse
	var err error

	// Check to make sure the label key is valid
	label.Key = strings.ToLower(label.Key)
	if label.Key != "app" && label.Key != "env" && label.Key != "role" && label.Key != "loc" {
		return newLabel, api, errors.New("label key is not app, env, role, or loc")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/labels")
	if err != nil {
		return newLabel, api, fmt.Errorf("create label - %s", err)
	}

	// Create payload
	labelJSON, err := json.Marshal(label)
	if err != nil {
		return newLabel, api, fmt.Errorf("create label - %s", err)
	}

	// Call the API
	api, err = apicall("POST", apiURL.String(), pce, labelJSON, false)
	if err != nil {
		return newLabel, api, fmt.Errorf("create label - %s", err)
	}

	// Unmarshal new label
	json.Unmarshal([]byte(api.RespBody), &newLabel)

	return newLabel, api, nil
}

// UpdateLabel updates an existing label in the Illumio PCE.
//
// The provided label struct must include an Href. The onyl values that will put in the JSON
// payload are Value, ExternalDataReference, and ExternalDataSet. Other values cannot be updated.
func UpdateLabel(pce PCE, label Label) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1" + label.Href)
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

	api, err = apicall("PUT", apiURL.String(), pce, labelJSON, false)
	if err != nil {
		return api, fmt.Errorf("update label - %s", err)
	}

	return api, nil
}
