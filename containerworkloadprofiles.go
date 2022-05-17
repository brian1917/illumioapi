package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

type ContainerWorkloadProfileAssignLabel struct {
	Href string `json:"href,omitempty"`
}

type ContainerWorkloadProfileLabel struct {
	Key        string                                  `json:"key,omitempty"`
	Assignment ContainerWorkloadProfileLabelAssignment `json:"assignment,omitempty"`
}
type ContainerWorkloadProfileLabelAssignment struct {
	Href  string `json:"href,omitempty"`
	Value string `json:"value,omitempty"`
}

// ContainerWorkloadProfile represents a container workload profile in the Illumio PCE
type ContainerWorkloadProfile struct {
	Href            string                                `json:"href,omitempty"`
	Name            string                                `json:"name,omitempty"`
	Namespace       string                                `json:"namespace,omitempty"`
	Description     string                                `json:"description,omitempty"`
	EnforcementMode string                                `json:"enforcement_mode,omitempty"`
	VisibilityLevel string                                `json:"visibility_level,omitempty"`
	Managed         *bool                                 `json:"managed,omitempty"`
	Linked          *bool                                 `json:"linked,omitempty"`
	AssignLabels    []ContainerWorkloadProfileAssignLabel `json:"assign_labels,omitempty"`
	Labels          []ContainerWorkloadProfileLabel       `json:"labels,omitempty"`
	CreatedAt       string                                `json:"created_at,omitempty"`
	CreatedBy       *CreatedBy                            `json:"created_by,omitempty"`
	UpdatedAt       string                                `json:"updated_at,omitempty"`
	UpdatedBy       *UpdatedBy                            `json:"updated_by,omitempty"`
}

// GetAllContainerWorkloadProfiles returns a slice of ContainerWorkloadProfiles in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
// QueryParameters can be passed as a map of [key]=value
func (p *PCE) GetAllContainerWorkloadProfiles(queryParameters map[string]string, containerClusterID string) ([]ContainerWorkloadProfile, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/container_clusters/" + containerClusterID + "/container_workload_profiles")
	if err != nil {
		return nil, api, fmt.Errorf("get all container workload profiles - %s", err)
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
		return nil, api, fmt.Errorf("get all container workload profiles - %s", err)
	}

	var containerWorkloadProfiles []ContainerWorkloadProfile
	json.Unmarshal([]byte(api.RespBody), &containerWorkloadProfiles)

	// Set up the VEN map
	p.ContainerWorkloadProfiles = make(map[string]ContainerWorkloadProfile)

	// If length is 500, re-run with async
	if len(containerWorkloadProfiles) >= 500 {
		// Call async
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all container clusters - %s", err)
		}
		// Unmarshal response to asyncWklds and return
		var asyncContainerWorkloadProfiles []ContainerWorkloadProfile
		json.Unmarshal([]byte(api.RespBody), &asyncContainerWorkloadProfiles)

		// Load the PCE with the returned workloads
		for _, c := range asyncContainerWorkloadProfiles {
			p.ContainerWorkloadProfiles[c.Href] = c
			p.ContainerWorkloadProfiles[c.Name] = c
		}
		p.ContainerWorkloadProfilesSlice = asyncContainerWorkloadProfiles

		return asyncContainerWorkloadProfiles, api, nil
	}

	// Load the PCE with the returned workloads
	for _, c := range containerWorkloadProfiles {
		p.ContainerWorkloadProfiles[c.Href] = c
		p.ContainerWorkloadProfiles[c.Name] = c
	}
	p.ContainerWorkloadProfilesSlice = containerWorkloadProfiles

	// Return if less than 500
	return containerWorkloadProfiles, api, nil
}
