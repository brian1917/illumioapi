package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// VEN is an Illumio agent.
// Duplicate workload fields have been left out
type VEN struct {
	Href             string            `json:"href,omitempty"`
	Name             *string           `json:"name,omitempty"`
	Description      *string           `json:"description,omitempty"`
	Hostname         *string           `json:"hostname,omitempty"`
	UID              string            `json:"uid,omitempty"`
	Status           string            `json:"status,omitempty"`
	Version          string            `json:"version,omitempty"`
	ActivationType   string            `json:"activation_type,omitempty"`
	ActivePceFqdn    string            `json:"active_pce_fqdn,omitempty"`
	TargetPceFqdn    *string           `json:"target_pce_fqdn,omitempty"`
	Workloads        *[]Workload       `json:"workloads,omitempty"`
	ContainerCluster *ContainerCluster `json:"container_cluster,omitempty"`
	VenType          string            `json:"ven_type,omitempty"`
	Conditions       *[]Condition      `json:"conditions,omitempty"`
}

// A condition is used by the VEN
// Conditions are never created or upgraded
type Condition struct {
	FirstReportedTimestamp time.Time    `json:"first_reported_timestamp"`
	LatestEvent            *LatestEvent `json:"latest_event"`
}

// A LatestEvent is for a condition
// LatestEvents are never created or updated.
type LatestEvent struct {
	NotificationType string    `json:"notification_type"`
	Severity         string    `json:"severity"`
	Href             string    `json:"href"`
	Info             Info      `json:"info"`
	Timestamp        time.Time `json:"timestamp"`
}

// VenUpgradeRequest is sent to the PCE to upgrade VENs
type VenUpgradeRequest struct {
	VENs    []VEN  `json:"vens"`
	Release string `json:"release"`
	DryRun  bool   `json:"dry_run"`
}

// VenUpgradeResponse is the PCE's response to a VEN upgrade request
type VenUpgradeResponse struct {
	VENUpgradeErrors []VenUpgradeError `json:"errors"`
}

// VenUpgradeError is used by VenUpgradeResponse
type VenUpgradeError struct {
	Token   string   `json:"token"`
	Message string   `json:"message"`
	Hrefs   []string `json:"hrefs"`
}

// GetVens returns a slice of VENs from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value"
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetVens(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("vens", false, queryParameters, &p.VENsSlice)
	if len(p.VENsSlice) >= 500 {
		p.VENsSlice = nil
		api, err = p.GetCollection("vens", true, queryParameters, &p.VENsSlice)
	}
	for _, v := range p.VENsSlice {
		p.VENs[v.Href] = v
		if v.Name != nil {
			p.VENs[*v.Name] = v
		}
		if v.Hostname != nil {
			p.VENs[*v.Hostname] = v
		}
		p.VENs[v.UID] = v
	}
	return api, err
}

// GetVenByHref returns the VEN with a specific href
func (p *PCE) GetVenByHref(href string) (ven VEN, api APIResponse, err error) {
	api, err = p.GetHref(href, &ven)
	return ven, api, err
}

// UpdateVEN updates an existing ven in the Illumio PCE
// The provided ven struct must include an href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateVen(ven VEN) (api APIResponse, err error) {

	// Build the new ven with only propertie we can update
	if strings.ToLower(ven.Status) != "active" && strings.ToLower(ven.Status) != "suspended" {
		return api, fmt.Errorf("%s is not a valid status. must be active or suspended", ven.Status)
	}
	venToUpdate := VEN{Href: ven.Href, Name: ven.Name, Description: ven.Description, Status: strings.ToLower(ven.Status)}

	return p.Put(&venToUpdate)
}

func (p *PCE) UpgradeVENs(vens []VEN, release string) (resp VenUpgradeResponse, api APIResponse, err error) {
	// Build the API URL
	apiURL, err := url.Parse("https://" + p.cleanFQDN() + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/vens/upgrade")
	if err != nil {
		return resp, api, fmt.Errorf("upgrade ven - %s", err)
	}

	// Build the venUpgrade
	venHrefs := []VEN{}
	for _, v := range vens {
		venHrefs = append(venHrefs, VEN{Href: v.Href})
	}
	venUpgrade := VenUpgradeRequest{Release: release, DryRun: false, VENs: venHrefs}

	// Call the API
	venUpgradeJSON, err := json.Marshal(venUpgrade)
	if err != nil {
		return resp, api, err
	}
	api, err = p.httpReq("PUT", apiURL.String(), venUpgradeJSON, false, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return resp, api, fmt.Errorf("upgrade ven - %s", err)
	}
	api.ReqBody = string(venUpgradeJSON)
	json.Unmarshal([]byte(api.RespBody), &resp)

	return resp, api, nil
}

// GetVenByHostname gets a VEN by the hostname
// Returns a blank VEN if no exact matches
// Uses GetVens so PCE VEN map and slice will be cleared.
func (p *PCE) GetVenByHostname(hostname string) (VEN, APIResponse, error) {
	a, err := p.GetVens(map[string]string{"hostname": hostname})
	if err != nil {
		return VEN{}, a, err
	}
	for _, ven := range p.VENsSlice {
		if PtrToVal(ven.Hostname) == hostname {
			return ven, a, nil
		}
	}
	return VEN{}, a, nil
}
