package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// GetAllWorkloadsQP returns a slice of workloads in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
// QueryParameters can be passed as a map of [key]=vale
func (p *PCE) GetAllContainerWorkloads(queryParameters map[string]string) ([]Workload, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/container_workloads")
	if err != nil {
		return nil, api, fmt.Errorf("get all workloads - %s", err)
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
		return nil, api, fmt.Errorf("get all workloads - %s", err)
	}

	var workloads []Workload
	json.Unmarshal([]byte(api.RespBody), &workloads)

	// If length is 500, re-run with async
	if len(workloads) >= 500 {
		// Call async
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all workloads - %s", err)
		}
		// Unmarshal response to asyncWklds and return
		var asyncWklds []Workload
		json.Unmarshal([]byte(api.RespBody), &asyncWklds)

		// Load the PCE with the returned workloads
		p.ContainerWorkloads = make(map[string]Workload)
		for _, w := range asyncWklds {
			p.ContainerWorkloads[w.Href] = w
			p.ContainerWorkloads[w.Hostname] = w
			p.ContainerWorkloads[w.Name] = w
		}
		p.ContainerWorkloadsSlice = asyncWklds

		return asyncWklds, api, nil
	}

	// Load the PCE with the returned workloads
	p.ContainerWorkloads = make(map[string]Workload)
	for _, w := range workloads {
		p.ContainerWorkloads[w.Href] = w
		p.ContainerWorkloads[w.Hostname] = w
		p.ContainerWorkloads[w.Name] = w
	}
	p.ContainerWorkloadsSlice = workloads

	// Return if less than 500
	return workloads, api, nil
}
