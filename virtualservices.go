package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// A VirtualService represents a Virtual Service in the Illumio PCE
type VirtualService struct {
	ApplyTo               string              `json:"apply_to,omitempty"`
	CreatedAt             string              `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy          `json:"created_by,omitempty"`
	DeletedAt             string              `json:"deleted_at,omitempty"`
	DeletedBy             *DeletedBy          `json:"deleted_by,omitempty"`
	Description           string              `json:"description,omitempty"`
	ExternalDataReference string              `json:"external_data_reference,omitempty"`
	ExternalDataSet       string              `json:"external_data_set,omitempty"`
	Href                  string              `json:"href,omitempty"`
	IPOverrides           []string            `json:"ip_overrides,omitempty"`
	Labels                []*Label            `json:"labels,omitempty"`
	Name                  string              `json:"name,omitempty"`
	PceFqdn               string              `json:"pce_fqdn,omitempty"`
	Service               *Service            `json:"service,omitempty"`
	ServiceAddresses      []*ServiceAddresses `json:"service_addresses,omitempty"`
	ServicePorts          []*ServicePort      `json:"service_ports,omitempty"`
	UpdateType            string              `json:"update_type,omitempty"`
	UpdatedAt             string              `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy          `json:"updated_by,omitempty"`
}

// ServiceAddresses are FQDNs for Virtual Services
type ServiceAddresses struct {
	IP          string   `json:"ip,omitempty"`
	Network     *Network `json:"network,omitempty"`
	Fqdn        string   `json:"fqdn,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Network represents a network in the PCE
type Network struct {
	Href string `json:"href,omitempty"`
	Name string `json:"name,omitempty"`
}

// GetAllVirtualServices returns a slice of all Virtual services of a
// specific provision status in the Illumio PCE.
//
// The queryParameters are map["parameter"]="value" (e.g., queryParameters["name"]="name123")
// The provision status must be "draft" or "active".
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func (p *PCE) GetAllVirtualServices(queryParameters map[string]string, provisionStatus string) ([]VirtualService, APIResponse, error) {
	var api APIResponse

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return nil, api, errors.New("get all Virtual services - provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/virtual_services")
	if err != nil {
		return nil, api, fmt.Errorf("get all Virtual services - %s", err)
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

// GetVirtualServiceByName returns a single Virtual Service that matches the name
// Using the queryParameters in GetAllVirtualServices reports partial matches on name values
// This method only returns a single value for exact match.
func (p *PCE) GetVirtualServiceByName(name string, provisionStatus string) (VirtualService, APIResponse, error) {
	qp := map[string]string{"name": name}
	vsMatches, api, err := p.GetAllVirtualServices(qp, provisionStatus)
	if err != nil {
		return VirtualService{}, api, err
	}
	for _, vs := range vsMatches {
		if vs.Name == name {
			return vs, api, nil
		}
	}
	return VirtualService{}, api, nil

}

// GetVirtualServiceByHref returns the virtualservice with a specific href
func (p *PCE) GetVirtualServiceByHref(href string) (VirtualService, APIResponse, error) {
	var virtualservice VirtualService
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + href)
	if err != nil {
		return virtualservice, api, fmt.Errorf("get virtualservice - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return virtualservice, api, fmt.Errorf("get virtualservice - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &virtualservice)

	return virtualservice, api, nil
}

// CreateVirtualService creates a new virtual service in the Illumio PCE.
func (p *PCE) CreateVirtualService(virtualService VirtualService) (VirtualService, APIResponse, error) {
	var newVirtualService VirtualService
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/draft/virtual_services")
	if err != nil {
		return newVirtualService, api, fmt.Errorf("create Virtual service - %s", err)
	}

	// Sanitize
	virtualService.Sanitize()

	// Call the API
	virtualServiceJSON, err := json.Marshal(virtualService)
	if err != nil {
		return newVirtualService, api, fmt.Errorf("create Virtual service - %s", err)
	}

	api.ReqBody = string(virtualServiceJSON)

	api, err = apicall("POST", apiURL.String(), *p, virtualServiceJSON, false)
	if err != nil {
		return newVirtualService, api, fmt.Errorf("create Virtual service - %s", err)
	}

	// Unmarshal new Virtual service
	json.Unmarshal([]byte(api.RespBody), &newVirtualService)

	return newVirtualService, api, nil
}

// UpdateVirtualService updates an existing virtual service in the Illumio PCE.
//
// The provided Virtual Service struct must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateVirtualService(virtualService VirtualService) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + virtualService.Href)
	if err != nil {
		return api, fmt.Errorf("update virtual service - %s", err)
	}

	virtualService.Sanitize()

	// Call the API
	virtualServiceJSON, err := json.Marshal(virtualService)
	if err != nil {
		return api, fmt.Errorf("update Virtual service - %s", err)
	}

	api.ReqBody = string(virtualServiceJSON)

	api, err = apicall("PUT", apiURL.String(), *p, virtualServiceJSON, false)
	if err != nil {
		return api, fmt.Errorf("update Virtual service - %s", err)
	}

	return api, nil
}

// BulkVS takes a bulk action on an array of workloads.
// Method must be create, update, or delete
func (p *PCE) BulkVS(virtualServices []VirtualService, method string) ([]APIResponse, error) {
	var apiResps []APIResponse
	var err error

	// Check on method
	method = strings.ToLower(method)
	if method != "create" && method != "update" && method != "delete" {
		return apiResps, errors.New("bulk vs error - method must be create, update, or delete")
	}

	// Sanitize update
	if method == "update" {
		sanitizedVSs := []VirtualService{}
		for _, vs := range virtualServices {
			vs.Sanitize()
			sanitizedVSs = append(sanitizedVSs, vs)
		}
		virtualServices = sanitizedVSs
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/draft/virtual_services/bulk_" + method)
	if err != nil {
		return apiResps, fmt.Errorf("bulk vs error - %s", err)
	}

	// If the method is delete, we can only send Hrefs
	if method == "delete" {
		hrefVSs := []VirtualService{}
		for _, vs := range virtualServices {
			hrefVSs = append(hrefVSs, VirtualService{Href: vs.Href})
		}
		// Re-assign virtual services to just the HREF
		virtualServices = hrefVSs
	}

	// Figure out how many API calls we need to make
	numAPICalls := int(math.Ceil(float64(len(virtualServices)) / 1000))

	// Build the array to be passed to the API
	apiArrays := [][]VirtualService{}
	for i := 0; i < numAPICalls; i++ {
		// Get 1,000 elements if this is not the last array
		if (i + 1) != numAPICalls {
			apiArrays = append(apiArrays, virtualServices[i*1000:(1+i)*1000])
			// Get the rest on the last array
		} else {
			apiArrays = append(apiArrays, virtualServices[i*1000:])
		}
	}

	// Call the API for each array
	for _, apiArray := range apiArrays {
		vsJSON, err := json.Marshal(apiArray)
		if err != nil {
			return apiResps, fmt.Errorf("bulk vs error - %s", err)
		}

		// Uncomment this line if you want to print the JSON object
		// fmt.Println(string(vsJson))

		api, err := apicall("PUT", apiURL.String(), *p, vsJSON, false)
		api.ReqBody = string(vsJSON)

		apiResps = append(apiResps, api)

		if err != nil {
			return apiResps, fmt.Errorf("bulk vs error - %s", err)
		}

	}

	return apiResps, nil
}

// Sanitize removes fields for an update
func (vs *VirtualService) Sanitize() {
	// Remove fields for marshaling an update
	vs.CreatedAt = ""
	vs.CreatedBy = nil
	vs.DeletedAt = ""
	vs.DeletedBy = nil
	vs.Href = ""
	vs.UpdateType = ""
	vs.UpdatedAt = ""
	vs.UpdatedBy = nil
	vs.PceFqdn = ""
	// Make the service HREF only
	if vs.Service != nil {
		vs.Service = &Service{Href: vs.Service.Href}
	}
	// Adjust the labels and services to be HREF only
	hrefOnlyLabels := []*Label{}
	for _, l := range vs.Labels {
		hrefOnlyLabels = append(hrefOnlyLabels, &Label{Href: l.Href})
	}
	vs.Labels = hrefOnlyLabels
}

// SetActive changes the HREF of the Virtual Service Object to Active
func (vs *VirtualService) SetActive() VirtualService {
	vs.Href = strings.ReplaceAll(vs.Href, "draft", "active")
	return *vs
}
