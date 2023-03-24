package illumioapi

import (
	"fmt"
	"strings"
)

// VirtualServer represents a VirtualServer in the PCE
type VirtualServer struct {
	Href                    string              `json:"href,omitempty"`
	Name                    string              `json:"name,omitempty"`
	Description             *string             `json:"description,omitempty"`
	DiscoveredVirtualServer *Href               `json:"discovered_virtual_server,omitempty"`
	DvsName                 string              `json:"dvs_name,omitempty"`
	DvsIdentifier           string              `json:"dvs_identifier,omitempty"`
	Labels                  *[]Label            `json:"labels,omitempty"`
	Service                 *Service            `json:"service,omitempty"`
	Providers               *ConsumerOrProvider `json:"providers,omitempty"`
	Mode                    string              `json:"mode,omitempty"`
	CreatedAt               string              `json:"created_at,omitempty"`
	CreatedBy               *Href               `json:"created_by,omitempty"`
	DeletedAt               string              `json:"deleted_at,omitempty"`
	DeletedBy               *Href               `json:"deleted_by,omitempty"`
	UpdatedAt               string              `json:"updated_at,omitempty"`
	UpdatedBy               *Href               `json:"updated_by,omitempty"`
}

// GetVirtualServers returns a slice of IP lists from the PCE. pStatus must be "draft" or "active".
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetVirtualServers(queryParameters map[string]string, pStatus string) (api APIResponse, err error) {
	// Validate pStatus
	pStatus = strings.ToLower(pStatus)
	if pStatus != "active" && pStatus != "draft" {
		return api, fmt.Errorf("invalid pStatus")
	}
	api, err = p.GetCollection("sec_policy/"+pStatus+"/virtual_servers", false, queryParameters, &p.VirtualServersSlice)
	if len(p.VirtualServersSlice) >= 500 {
		api, err = p.GetCollection("sec_policy/"+pStatus+"/virtual_servers", true, queryParameters, &p.VirtualServersSlice)
	}
	p.VirtualServers = make(map[string]VirtualServer)
	for _, v := range p.VirtualServersSlice {
		p.VirtualServers[v.Href] = v
		p.VirtualServers[v.Name] = v
	}
	return api, err
}
