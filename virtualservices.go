package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// A VirtualService represents a Virtual Service in the Illumio PCE
type VirtualService struct {
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

// A ServiceBinding represents a Service Binding in the Illumio PCE
type ServiceBinding struct {
}

// GetAllVirtualServices returns a slice of all Virtual services of a
// specific provision status in the Illumio PCE.
//
// The pvoision status must be "draft" or "active".
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func (p *PCE) GetAllVirtualServices(provisionStatus string) ([]VirtualService, APIResponse, error) {
	var api APIResponse

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return nil, api, errors.New("get all Virtual services - provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v1/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/virtual_services")
	if err != nil {
		return nil, api, fmt.Errorf("get all Virtual services - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all Virtual services - %s", err)
	}

	var virtualServices []VirtualService
	json.Unmarshal([]byte(api.RespBody), &virtualServices)

	// If length is 500, re-run with async
	if len(virtualServices) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all Virtual services - %s", err)
		}

		// Unmarshal response to struct
		var asyncVirtualServices []VirtualService
		json.Unmarshal([]byte(api.RespBody), &asyncVirtualServices)

		return asyncVirtualServices, api, nil
	}

	// Return if there are less than 500
	return virtualServices, api, nil
}

// CreateBoundService creates a new Virtual service in the Illumio PCE.
func (p *PCE) CreateBoundService(virtualService VirtualService) (VirtualService, APIResponse, error) {
	var newBoundService VirtualService
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v1/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/draft/virtual_services")
	if err != nil {
		return newBoundService, api, fmt.Errorf("create Virtual service - %s", err)
	}

	// Call the API
	virtualServiceJSON, err := json.Marshal(virtualService)
	if err != nil {
		return newBoundService, api, fmt.Errorf("create Virtual service - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), *p, virtualServiceJSON, false)
	if err != nil {
		return newBoundService, api, fmt.Errorf("create Virtual service - %s", err)
	}

	// Unmarshal new Virtual service
	json.Unmarshal([]byte(api.RespBody), &newBoundService)

	return newBoundService, api, nil
}

// UpdateBoundService updates an existing Virtual service in the Illumio PCE.
//
// The provided BoundService struct must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateBoundService(virtualService VirtualService) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v1" + virtualService.Href)
	if err != nil {
		return api, fmt.Errorf("update Virtual service - %s", err)
	}

	// Remove fields for marshaling an update
	virtualService.CreatedAt = ""
	virtualService.CreatedBy = nil
	virtualService.Href = ""
	virtualService.UpdateType = ""
	virtualService.UpdatedAt = ""
	virtualService.UpdatedBy = nil

	// Call the API
	virtualServiceJSON, err := json.Marshal(virtualService)
	if err != nil {
		return api, fmt.Errorf("update Virtual service - %s", err)
	}

	api, err = apicall("PUT", apiURL.String(), *p, virtualServiceJSON, false)
	if err != nil {
		return api, fmt.Errorf("update Virtual service - %s", err)
	}

	return api, nil
}
