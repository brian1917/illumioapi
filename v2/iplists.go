package illumioapi

import (
	"fmt"
	"strings"
)

// IPList represents an IP List in the PCE.
type IPList struct {
	Href                  string     `json:"href,omitempty"`
	Name                  string     `json:"name,omitempty"`
	Description           *string    `json:"description,omitempty"`
	IPRanges              *[]IPRange `json:"ip_ranges,omitempty"`
	FQDNs                 *[]FQDN    `json:"fqdns,omitempty"`
	Size                  int        `json:"size,omitempty"`
	ExternalDataReference *string    `json:"external_data_reference,omitempty"`
	ExternalDataSet       *string    `json:"external_data_set,omitempty"`
	CreatedAt             string     `json:"created_at,omitempty"`
	CreatedBy             *Href      `json:"created_by,omitempty"`
	DeletedAt             string     `json:"deleted_at,omitempty"`
	DeletedBy             *Href      `json:"deleted_by,omitempty"`
	UpdatedAt             string     `json:"updated_at,omitempty"`
	UpdatedBy             *Href      `json:"updated_by,omitempty"`
}

// IPRange repsents one of the IP ranges of an IP List.
// IPRanges are never updated in place (not using pointers)
type IPRange struct {
	Description string `json:"description,omitempty"`
	Exclusion   bool   `json:"exclusion,omitempty"`
	FromIP      string `json:"from_ip,omitempty"`
	ToIP        string `json:"to_ip,omitempty"`
}

// FQDN represents an FQDN in an IPList
type FQDN struct {
	FQDN string `json:"fqdn,omitempty"`
}

// GetIPLists returns a slice of IP lists from the PCE. pStatus must be "draft" or "active".
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetIPLists(queryParameters map[string]string, pStatus string) (api APIResponse, err error) {
	// Validate pStatus
	pStatus = strings.ToLower(pStatus)
	if pStatus != "active" && pStatus != "draft" {
		return api, fmt.Errorf("invalid pStatus")
	}
	api, err = p.GetCollection("/sec_policy/"+pStatus+"/ip_lists", false, queryParameters, &p.IPListsSlice)
	if len(p.IPListsSlice) >= 500 {
		p.IPListsSlice = nil
		api, err = p.GetCollection("/sec_policy/"+pStatus+"/ip_lists", true, queryParameters, &p.IPListsSlice)
	}
	p.IPLists = make(map[string]IPList)
	for _, ipl := range p.IPListsSlice {
		p.IPLists[ipl.Href] = ipl
		p.IPLists[ipl.Name] = ipl
	}
	return api, err
}

// GetIPListByName queries returns the IP List based on name. A blank IP List is return if no exact match.
// This method leverages GetIPLists. Any matching named IP lists will be stored in the PCE object.
func (p *PCE) GetIPListByName(name string, pStatus string) (IPList, APIResponse, error) {
	api, err := p.GetIPLists(map[string]string{"name": name}, pStatus)
	if err != nil {
		return IPList{}, api, err
	}

	for _, ipl := range p.IPListsSlice {
		if ipl.Name == name {
			return ipl, api, nil
		}
	}
	// If there is no match we are going to return an empty IP List
	return IPList{}, api, nil
}

// CreateIPList creates a new IP List in the PCE.
func (p *PCE) CreateIPList(ipList IPList) (createdIPL IPList, api APIResponse, err error) {
	api, err = p.Post("sec_policy/draft/ip_lists", &ipList, &createdIPL)
	return createdIPL, api, err
}

// UpdateIPList updates an existing IP List in the PCE.
// The provided IP List must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateIPList(ipList IPList) (APIResponse, error) {
	ipList.CreatedAt = ""
	ipList.CreatedBy = nil
	ipList.DeletedAt = ""
	ipList.DeletedBy = nil
	ipList.UpdatedAt = ""
	ipList.UpdatedBy = nil

	api, err := p.Put(&ipList)
	return api, err
}
