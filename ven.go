package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VEN represents a VEN in the Illumio PCE.
// Not including duplicated fields in a workload - labels, OS information, interfaces, etc.
type VEN struct {
	Href             string            `json:"href,omitempty"`
	Name             string            `json:"name,omitempty"`
	Description      string            `json:"description,omitempty"`
	Hostname         string            `json:"hostname,omitempty"`
	UID              string            `json:"uid,omitempty"`
	Status           string            `json:"status,omitempty"`
	Version          string            `json:"version,omitempty"`
	ActivationType   string            `json:"activation_type,omitempty"`
	ActivePceFqdn    string            `json:"active_pce_fqdn,omitempty"`
	TargetPceFqdn    string            `json:"target_pce_fqdn,omitempty"`
	Workloads        *[]*Workload      `json:"workloads,omitempty"`
	ContainerCluster *ContainerCluster `json:"container_cluster,omitempty"`
}

type VENUpgrade struct {
	VENs    []VEN  `json:"vens"`
	Release string `json:"release"`
	DryRun  bool   `json:"dry_run"`
}

type VENUpgradeResp struct {
	VENUpgradeErrors []VENUpgradeError `json:"errors"`
}

type VENUpgradeError struct {
	Token   string   `json:"token"`
	Message string   `json:"message"`
	Hrefs   []string `json:"hrefs"`
}

// GetAllVens returns a slice of VENs in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
// QueryParameters can be passed as a map of [key]=vale
func (p *PCE) GetAllVens(queryParameters map[string]string) ([]VEN, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/vens")
	if err != nil {
		return nil, api, fmt.Errorf("get all vens - %s", err)
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
		return nil, api, fmt.Errorf("get all vens - %s", err)
	}

	var vens []VEN
	json.Unmarshal([]byte(api.RespBody), &vens)

	// Set up the VEN map
	p.VENs = make(map[string]VEN)

	// If length is 500, re-run with async
	if len(vens) >= 500 {
		// Call async
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all vens - %s", err)
		}
		// Unmarshal response to asyncWklds and return
		var asyncVENs []VEN
		json.Unmarshal([]byte(api.RespBody), &asyncVENs)

		// Load the PCE with the returned workloads
		for _, v := range asyncVENs {
			p.VENs[v.Href] = v
			p.VENs[v.Name] = v
		}
		p.VENsSlice = asyncVENs

		return asyncVENs, api, nil
	}

	// Load the PCE with the returned workloads
	for _, v := range vens {
		p.VENs[v.Href] = v
		p.VENs[v.Name] = v
	}
	p.VENsSlice = vens

	// Return if less than 500
	return vens, api, nil
}

// UpdateVEN updates an existing ven in the Illumio PCE
// The provided ven struct must include an href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateVen(ven VEN) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + ven.Href)
	if err != nil {
		return api, fmt.Errorf("update ven - %s", err)
	}

	// Build the new ven with only propertie we can update
	if strings.ToLower(ven.Status) != "active" && strings.ToLower(ven.Status) != "suspended" {
		return api, fmt.Errorf("%s is not a valid status. must be active or suspended", ven.Status)
	}
	venToUpdate := VEN{Name: ven.Name, Description: ven.Description, Status: strings.ToLower(ven.Status)}

	// Call the API
	venJSON, err := json.Marshal(venToUpdate)
	if err != nil {
		return api, fmt.Errorf("update ven - %s", err)
	}
	api.ReqBody = string(venJSON)

	api, err = apicall("PUT", apiURL.String(), *p, venJSON, false)
	if err != nil {
		return api, fmt.Errorf("update ven - %s", err)
	}

	return api, nil
}

func (p *PCE) UpgradeVENs(vens []VEN, release string) (VENUpgradeResp, APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/vens/upgrade")
	if err != nil {
		return VENUpgradeResp{}, api, fmt.Errorf("upgrade ven - %s", err)
	}

	// Build the venUpgrade
	venHrefs := []VEN{}
	for _, v := range vens {
		venHrefs = append(venHrefs, VEN{Href: v.Href})
	}
	venUpgrade := VENUpgrade{Release: release, DryRun: false, VENs: venHrefs}

	// Call the API
	venUpgradeJSON, err := json.Marshal(venUpgrade)
	if err != nil {
		return VENUpgradeResp{}, api, fmt.Errorf("upgrade ven - %s", err)
	}
	api.ReqBody = string(venUpgradeJSON)

	api, err = apicall("PUT", apiURL.String(), *p, venUpgradeJSON, false)
	if err != nil {
		return VENUpgradeResp{}, api, fmt.Errorf("upgrade ven - %s", err)
	}
	var resp VENUpgradeResp
	json.Unmarshal([]byte(api.RespBody), &resp)

	return resp, api, nil
}
