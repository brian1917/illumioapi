package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// GetAllADUserGroups gets all user groups in the PCE
func (p *PCE) GetAllADUserGroups() ([]ConsumingSecurityPrincipals, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/security_principals")
	if err != nil {
		return nil, APIResponse{}, fmt.Errorf("GetAllADUserGroups - %s", err)
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("GetAllADUserGroups - %s", err)
	}

	// Unmarshal response to struct
	var adUserGroups []ConsumingSecurityPrincipals
	json.Unmarshal([]byte(api.RespBody), &adUserGroups)

	// If adUserGroups is 500, re-run with async
	if len(adUserGroups) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("adUserGroups - %s", err)
		}

		// Unmarshal response to struct
		var asyncADUserGroups []ConsumingSecurityPrincipals
		json.Unmarshal([]byte(api.RespBody), &asyncADUserGroups)

		return asyncADUserGroups, api, nil
	}

	// Return if less than 500
	return adUserGroups, api, nil
}

// CreateADUserGroup creates a user group policy object in the PCE
func (p *PCE) CreateADUserGroup(g ConsumingSecurityPrincipals) (ConsumingSecurityPrincipals, APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/security_principals")
	if err != nil {
		return ConsumingSecurityPrincipals{}, api, fmt.Errorf("CreateADUserGroup - %s", err)
	}

	// Create payload
	userGroupJSON, err := json.Marshal(g)
	if err != nil {
		return ConsumingSecurityPrincipals{}, api, fmt.Errorf("CreateADUserGroup - %s", err)
	}

	// Call the API
	api, err = apicall("POST", apiURL.String(), *p, userGroupJSON, false)
	if err != nil {
		return ConsumingSecurityPrincipals{}, api, fmt.Errorf("CreateADUserGroup - %s", err)
	}

	// Unmarshal new label
	var newGroup ConsumingSecurityPrincipals
	json.Unmarshal([]byte(api.RespBody), &newGroup)

	return newGroup, api, nil
}
