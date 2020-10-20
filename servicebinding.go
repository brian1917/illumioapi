package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// A ServiceBinding binds a worklad to a Virtual Service
type ServiceBinding struct {
	Href           string          `json:"href,omitempty"`
	VirtualService VirtualService  `json:"virtual_service"`
	Workload       Workload        `json:"workload"`
	PortOverrides  []PortOverrides `json:"port_overrides"`
}

// PortOverrides override a port on a virtual service binding.
type PortOverrides struct {
	Port    int `json:"port"`
	Proto   int `json:"proto"`
	NewPort int `json:"new_port"`
}

// GetAllServiceBindings returns a slice of all workload bindings for a virtual service.
//
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func (p *PCE) GetAllServiceBindings(virtualService VirtualService) ([]ServiceBinding, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/service_bindings")
	if err != nil {
		return nil, api, fmt.Errorf("get all service bindings - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all service bindings - %s", err)
	}

	var serviceBindings []ServiceBinding
	json.Unmarshal([]byte(api.RespBody), &serviceBindings)

	// If length is 500, re-run with async
	if len(serviceBindings) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all service bindings - %s", err)
		}

		// Unmarshal response to struct
		var asyncServiceBindings []ServiceBinding
		json.Unmarshal([]byte(api.RespBody), &asyncServiceBindings)

		return asyncServiceBindings, api, nil
	}

	// Return if there are less than 500
	return serviceBindings, api, nil
}

// CreateServiceBinding binds new workloads to a virtual service
func (p *PCE) CreateServiceBinding(serviceBindings []ServiceBinding, virtualService VirtualService) ([]ServiceBinding, APIResponse, error) {
	var newServBindings []ServiceBinding
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/service_bindings")
	if err != nil {
		return newServBindings, api, fmt.Errorf("create service binding - %s", err)
	}

	// Sanitize Bindings
	sanSBs := []ServiceBinding{}
	for _, sb := range serviceBindings {
		sb.sanitizeBindings()
		sanSBs = append(sanSBs, sb)
	}
	serviceBindings = sanSBs

	// Call the API
	sbJSON, err := json.Marshal(serviceBindings)
	if err != nil {
		return newServBindings, api, fmt.Errorf("create service binding - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), *p, sbJSON, false)
	if err != nil {
		return newServBindings, api, fmt.Errorf("create servince binding - %s", err)
	}

	// Unmarshal new Virtual service
	json.Unmarshal([]byte(api.RespBody), &newServBindings)

	return newServBindings, api, nil
}

// SanitizeBindings preps bindings for update or create
func (sb *ServiceBinding) sanitizeBindings() {
	sb.Href = ""
	sb.VirtualService = VirtualService{Href: sb.VirtualService.SetActive().Href}
	sb.Workload = Workload{Href: sb.Workload.Href}
}
