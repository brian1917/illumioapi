package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// VirtualServer represents a VirtualServer in the PCE
type VirtualServer struct {
	Href                    string                   `json:"href,omitempty"`
	CreatedAt               string                   `json:"created_at,omitempty"`
	UpdatedAt               string                   `json:"updated_at,omitempty"`
	DeletedAt               string                   `json:"deleted_at,omitempty"`
	CreatedBy               *CreatedBy               `json:"created_by,omitempty"`
	UpdatedBy               *UpdatedBy               `json:"updated_by,omitempty"`
	DeletedBy               *DeletedBy               `json:"deleted_by,omitempty"`
	Name                    string                   `json:"name,omitempty"`
	Description             string                   `json:"description,omitempty"`
	DiscoveredVirtualServer *DiscoveredVirtualServer `json:"discovered_virtual_server,omitempty"`
	DvsName                 string                   `json:"dvs_name,omitempty"`
	DvsIdentifier           string                   `json:"dvs_identifier,omitempty"`
	Labels                  []*Label                 `json:"labels,omitempty"`
	Service                 *Service                 `json:"service,omitempty"`
	Providers               []interface{}            `json:"providers,omitempty"`
	Mode                    string                   `json:"mode,omitempty"`
}

// DiscoveredVirtualServer is part of a Virtual Server
type DiscoveredVirtualServer struct {
	Href string `json:"href"`
}

// GetAllVirtualServers returns a slice of virtual servers in the Illumio PCE.
// provisionStatus must be "draft" or "active"
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
func (p *PCE) GetAllVirtualServers(provisionStatus string) ([]VirtualServer, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/virtual_servers")
	if err != nil {
		return nil, api, fmt.Errorf("get all workloads - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all virtualservers - %s", err)
	}

	var virtualServers []VirtualServer
	json.Unmarshal([]byte(api.RespBody), &virtualServers)

	// If length is 500, re-run with async
	if len(virtualServers) >= 500 {
		// Call async
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all virtualservers - %s", err)
		}
		// Unmarshal response to asyncWklds and return
		var asyncVS []VirtualServer
		json.Unmarshal([]byte(api.RespBody), &asyncVS)

		return asyncVS, api, nil
	}

	// Return if less than 500
	return virtualServers, api, nil
}
