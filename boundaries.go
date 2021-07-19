package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

type EnforcementBoundary struct {
	Href            string            `json:"href,omitempty"`
	Name            string            `json:"name,omitempty"`
	Providers       []Providers       `json:"providers,omitempty"`
	Consumers       []Consumers       `json:"consumers,omitempty"`
	IngressServices []IngressServices `json:"ingress_services,omitempty"`
}

// CreateEnforcementBoundary creates a new enforcement boundary in the Illumio PCE
func (p *PCE) CreateEnforcementBoundary(enforcementBoundary EnforcementBoundary) (EnforcementBoundary, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/draft/enforcement_boundaries")
	if err != nil {
		return EnforcementBoundary{}, APIResponse{}, fmt.Errorf("create enforcement boundary - %s", err)
	}

	// Call the API
	enforcementBoundaryJson, err := json.Marshal(enforcementBoundary)
	if err != nil {
		return EnforcementBoundary{}, APIResponse{}, fmt.Errorf("create enforcement boundary - %s", err)
	}
	api, err := apicall("POST", apiURL.String(), *p, enforcementBoundaryJson, false)
	api.ReqBody = string(enforcementBoundaryJson)
	if err != nil {
		return EnforcementBoundary{}, api, fmt.Errorf("create enforcement boundary - %s", err)
	}

	// Marshal JSON
	var newEB EnforcementBoundary
	json.Unmarshal([]byte(api.RespBody), &newEB)

	return newEB, api, nil
}
