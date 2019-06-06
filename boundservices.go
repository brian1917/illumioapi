package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// A BoundService represents a Bound Service in the Illumio PCE
type BoundService struct {
	ApplyTo               string     `json:"apply_to,omitempty"`
	CreatedAt             string     `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy `json:"created_by,omitempty"`
	Description           string     `json:"description,omitempty"`
	ExternalDataReference string     `json:"external_data_reference,omitempty"`
	ExternalDataSet       string     `json:"external_data_set,omitempty"`
	Href                  string     `json:"href,omitempty"`
	IPOverrides           []string   `json:"ip_overrides,omitempty"`
	Labels                []*Label   `json:"labels,omitempty"`
	Name                  string     `json:"name,omitempty"`
	Service               *Service   `json:"service,omitempty"`
	UpdateType            string     `json:"update_type,omitempty"`
	UpdatedAt             string     `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy `json:"updated_by,omitempty"`
}

// GetAllBoundServices returns a slice of all bound services of a
// specific provision status in the Illumio PCE.
//
// The pvoision status must be "draft" or "active".
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func GetAllBoundServices(pce PCE, provisionStatus string) ([]BoundService, APIResponse, error) {
	var boundServices []BoundService
	var api APIResponse

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return boundServices, api, errors.New("get all bound services - provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/" + provisionStatus + "/bound_services")
	if err != nil {
		return boundServices, api, fmt.Errorf("get all bound services - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return boundServices, api, fmt.Errorf("get all bound services - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &boundServices)

	// If length is 500, re-run with async
	if len(boundServices) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return boundServices, api, fmt.Errorf("get all bound services - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &boundServices)
	}

	return boundServices, api, nil
}

// CreateBoundService creates a new bound service in the Illumio PCE.
func CreateBoundService(pce PCE, boundService BoundService) (BoundService, APIResponse, error) {
	var newBoundService BoundService
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/draft/bound_services")
	if err != nil {
		return newBoundService, api, fmt.Errorf("create bound service - %s", err)
	}

	// Call the API
	boundServiceJSON, err := json.Marshal(boundService)
	if err != nil {
		return newBoundService, api, fmt.Errorf("create bound service - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), pce, boundServiceJSON, false)
	if err != nil {
		return newBoundService, api, fmt.Errorf("create bound service - %s", err)
	}

	// Unmarshal new bound service
	json.Unmarshal([]byte(api.RespBody), &newBoundService)

	return newBoundService, api, nil
}

// UpdateBoundService updates an existing bound service in the Illumio PCE.
//
// The provided BoundService struct must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func UpdateBoundService(pce PCE, boundService BoundService) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1" + boundService.Href)
	if err != nil {
		return api, fmt.Errorf("update bound service - %s", err)
	}

	// Remove fields for marshaling an update
	boundService.CreatedAt = ""
	boundService.CreatedBy = nil
	boundService.Href = ""
	boundService.UpdateType = ""
	boundService.UpdatedAt = ""
	boundService.UpdatedBy = nil

	// Call the API
	boundServiceJSON, err := json.Marshal(boundService)
	if err != nil {
		return api, fmt.Errorf("update bound service - %s", err)
	}

	api, err = apicall("PUT", apiURL.String(), pce, boundServiceJSON, false)
	if err != nil {
		return api, fmt.Errorf("update bound service - %s", err)
	}

	return api, nil
}
