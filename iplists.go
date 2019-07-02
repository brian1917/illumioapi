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
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/active/ip_lists")
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
	apiURL, err = url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/draft/ip_lists")
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

// getAllIPLists is an internal function to get all IP Lists
// of a specific provision status.
//
// The provision status must be "draft" or "active".
// The first call does not use the async option.
// If the response array length is >=500, it is re-run enabling async.
func getAllIPLists(pce PCE, provisionStatus string) ([]IPList, APIResponse, error) {
	var ipLists []IPList
	var api APIResponse

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return ipLists, api, errors.New("get all iplists - provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/" + provisionStatus + "/ip_lists")
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

// GetAllIPLists returns a slice of all IPLists in the PCE.
// The function combines the query to get draft and active IP Lists.
// If there are more than 500 of either, async queries will run.
// The []APIResponse will have two entries - first is for draft, second for active.
// The HREF will indicate if it's active or draft.
func GetAllIPLists(pce PCE) ([]IPList, []APIResponse, error) {
	var allIPLists []IPList

	draftIPLists, a1, err := getAllIPLists(pce, "draft")
	if err != nil {
		return nil, nil, fmt.Errorf("get all iplists - draft - %s", err)
	}
	activeIPLists, a2, err := getAllIPLists(pce, "active")
	if err != nil {
		return nil, nil, fmt.Errorf("get all iplists - active - %s", err)
	}

	allIPLists = append(append(allIPLists, draftIPLists...), activeIPLists...)

	return allIPLists, []APIResponse{a1, a2}, nil
}

// GetAllDraftIPLists returns a slice of draft IPLists
// If there are more than 500 IP Lists, async will run.
func GetAllDraftIPLists(pce PCE) ([]IPList, APIResponse, error) {

	i, a, err := getAllIPLists(pce, "draft")
	if err != nil {
		return nil, a, fmt.Errorf("get all draft iplists - %s", err)
	}

	return i, a, nil
}

// GetAllActiveIPLists returns a slice of draft IPLists
// If there are more than 500 IP Lists, async will run.
func GetAllActiveIPLists(pce PCE) ([]IPList, APIResponse, error) {

	i, a, err := getAllIPLists(pce, "active")
	if err != nil {
		return nil, a, fmt.Errorf("get all active iplists - %s", err)
	}

	return i, a, nil
}

// CreateIPList creates a new IP List in the Illumio PCE.
//
// The function will not remove properties not in the POST schema (e.g., CreatedAt)
func CreateIPList(pce PCE, ipList IPList) (IPList, APIResponse, error) {
	var newIPList IPList
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/draft/ip_lists")
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
// The provided IPList struct must include an Href.
// The function will remove properties not included in the PUT schema.
func UpdateIPList(pce PCE, iplist IPList) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1" + iplist.Href)
	if err != nil {
		return api, fmt.Errorf("update iplist - %s", err)
	}

	// Remove fields that should be empty for the PUT schema
	iplist.CreatedAt = ""
	iplist.CreatedBy = nil
	iplist.DeletedAt = ""
	iplist.DeletedBy = nil
	iplist.Href = ""
	iplist.UpdatedAt = ""
	iplist.UpdatedBy = nil

	// Marshal JSON
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
