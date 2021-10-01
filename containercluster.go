package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// ContainerCluster represents a container cluster in the Illumio PCE
type ContainerCluster struct {
	Href             string `json:"href,omitempty"`
	Name             string `json:"name,omitempty"`
	Description      string `json:"description,omitempty"`
	ContainerRuntime string `json:"container_runtime,omitempty"`
	ManagerType      string `json:"manager_type,omitempty"`
	Online           *bool  `json:"online,omitempty"`
	KubelinkVersion  string `json:"kubelink_version,omitempty"`
	PceFqdn          string `json:"pce_fqdn,omitempty"`
}

// GetAllContainerClusters returns a slice of ContainerCluster in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
// QueryParameters can be passed as a map of [key]=vale
func (p *PCE) GetAllContainerClusters(queryParameters map[string]string) ([]ContainerCluster, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/container_clusters")
	if err != nil {
		return nil, api, fmt.Errorf("get all container clusters - %s", err)
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
		return nil, api, fmt.Errorf("get all container clusters - %s", err)
	}

	var containerClusters []ContainerCluster
	json.Unmarshal([]byte(api.RespBody), &containerClusters)

	// Set up the VEN map
	p.ContainerClusters = make(map[string]ContainerCluster)

	// If length is 500, re-run with async
	if len(containerClusters) >= 500 {
		// Call async
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all container clusters - %s", err)
		}
		// Unmarshal response to asyncWklds and return
		var asyncContainerClusters []ContainerCluster
		json.Unmarshal([]byte(api.RespBody), &asyncContainerClusters)

		// Load the PCE with the returned workloads
		for _, c := range asyncContainerClusters {
			p.ContainerClusters[c.Href] = c
			p.ContainerClusters[c.Name] = c
		}
		p.ContainerClustersSlice = asyncContainerClusters

		return asyncContainerClusters, api, nil
	}

	// Load the PCE with the returned workloads
	for _, c := range containerClusters {
		p.ContainerClusters[c.Href] = c
		p.ContainerClusters[c.Name] = c
	}
	p.ContainerClustersSlice = containerClusters

	// Return if less than 500
	return containerClusters, api, nil
}
