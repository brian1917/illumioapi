package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// IPRange repsents one of the IP ranges of an IP List.
type IPRange struct {
	Description string `json:"description,omitempty"`
	Exclusion   bool   `json:"exclusion,omitempty"`
	FromIP      string `json:"from_ip,omitempty"`
	ToIP        string `json:"to_ip,omitempty"`
}

// IPList represents an IP List in the Illumio PCE.
type IPList struct {
	CreatedAt             string     `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy `json:"created_by,omitempty"`
	DeletedAt             string     `json:"deleted_at,omitempty"`
	DeletedBy             *DeletedBy `json:"deleted_by,omitempty"`
	Description           string     `json:"description,omitempty"`
	ExternalDataReference string     `json:"external_data_reference,omitempty"`
	ExternalDataSet       string     `json:"external_data_set,omitempty"`
	Href                  string     `json:"href,omitempty"`
	IPRanges              []*IPRange `json:"ip_ranges,omitempty"`
	Name                  string     `json:"name,omitempty"`
	UpdatedAt             string     `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy `json:"updated_by,omitempty"`
}

// GetIPList queries returns the IP List based on name. Provisioned IP lists checked before draft
func GetIPList(pce PCE, name string) (IPList, APIResponse, error) {
	var ipList IPList
	var api APIResponse
	var activeIPLists, draftIPLists []IPList

	// Active IP Lists
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/active/ip_lists")
	if err != nil {
		return ipList, api, fmt.Errorf("get iplist - %s", err)
	}
	q := apiURL.Query()
	q.Set("name", name)
	apiURL.RawQuery = q.Encode()
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return ipList, api, fmt.Errorf("get iplist - %s", err)
	}
	json.Unmarshal([]byte(api.RespBody), &activeIPLists)

	// Draft IP Lists
	apiURL, err = url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/draft/ip_lists")
	if err != nil {
		return ipList, api, fmt.Errorf("get iplist - %s", err)
	}
	q = apiURL.Query()
	q.Set("name", name)
	apiURL.RawQuery = q.Encode()
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return ipList, api, fmt.Errorf("get iplist - %s", err)
	}
	json.Unmarshal([]byte(api.RespBody), &draftIPLists)

	// Combine into a single slice with active first
	ipLists := append(activeIPLists, draftIPLists...)

	// Look for our match and return the first one
	for _, ipl := range ipLists {
		if ipl.Name == name {
			return ipl, api, nil
		}
	}

	// If there is no match we are going to return an empty IP List
	return ipList, api, err

}

// GetAllIPLists returns a slice of all IP Lists of a
// specific provision status in the Illumio PCE.
//
// The pvoision status must be "draft" or "active".
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func GetAllIPLists(pce PCE, provisionStatus string) ([]IPList, APIResponse, error) {
	var ipLists []IPList
	var api APIResponse

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return ipLists, api, errors.New("get all iplists - provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/" + provisionStatus + "/ip_lists")
	if err != nil {
		return ipLists, api, fmt.Errorf("get all iplists - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return ipLists, api, fmt.Errorf("get all iplists - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &ipLists)

	// If length is 500, re-run with async
	if len(ipLists) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return ipLists, api, fmt.Errorf("get all iplists - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &ipLists)
	}

	return ipLists, api, nil
}

// CreateIPList creates a new IP List in the Illumio PCE.
func CreateIPList(pce PCE, ipList IPList) (IPList, APIResponse, error) {
	var newIPList IPList
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/draft/ip_lists")
	if err != nil {
		return newIPList, api, fmt.Errorf("create iplist - %s", err)
	}

	// Call the API
	ipListJSON, err := json.Marshal(ipList)
	if err != nil {
		return newIPList, api, fmt.Errorf("create iplist - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), pce, ipListJSON, false)
	if err != nil {
		return newIPList, api, fmt.Errorf("create iplist - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &newIPList)

	return newIPList, api, nil
}

// UpdateIPList updates an existing IP List in the Illumio PCE.
//
// The provided IPList struct must include an Href. The following fields will
// be disregarded in the JSON payload because they cannot be updated: CreatedAt,
// CreatedBy, DeletedAt, DeletedBy, UpdateType, UpdatedAt, UpdatedBy.
func UpdateIPList(pce PCE, iplist IPList) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1" + iplist.Href)
	if err != nil {
		return api, fmt.Errorf("update iplist - %s", err)
	}

	// Marshall Payload without the HREF
	iplist.CreatedAt = ""
	iplist.CreatedBy = nil
	iplist.DeletedAt = ""
	iplist.DeletedBy = nil
	iplist.Href = ""
	iplist.UpdatedAt = ""
	iplist.UpdatedBy = nil

	ipListJSON, err := json.Marshal(iplist)
	if err != nil {
		return api, fmt.Errorf("update iplist - %s", err)
	}

	// Call the API
	api, err = apicall("PUT", apiURL.String(), pce, ipListJSON, false)
	if err != nil {
		return api, fmt.Errorf("update iplist - %s", err)
	}

	return api, nil
}
