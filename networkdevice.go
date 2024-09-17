package illumioapi

import (
	"fmt"
	"strings"
	"time"
)

// NetworkDevice is the data structure for all NEN Switch Objects.
type NetworkDevice struct {
	Href                  string `json:"href,omitempty"`
	SupportedEndpointType string `json:"supported_endpoint_type,omitempty"`
	Config                struct {
		DeviceType   string `json:"device_type,omitempty"`
		Name         string `json:"name,omitempty"`
		Manufacturer string `json:"manufacturer,omitempty"`
		Model        string `json:"model,omitempty"`
		RulesFormat  string `json:"rules_format,omitempty"`
	} `json:"config,omitempty"`
	Configure                                   bool      `json:"configure,omitempty"`
	EnforcementInstructionsDataHref             string    `json:"enforcement_instructions_data_href,omitempty"`
	EnforcementInstructionsDataTimestamp        time.Time `json:"enforcement_instructions_data_timestamp,omitempty"`
	EnforcementInstructionsGenerationInProgress bool      `json:"enforcement_instructions_generation_in_progress,omitempty"`
	EnforcementInstructionsAckHref              string    `json:"enforcement_instructions_ack_href,omitempty"`
	EnforcementInstructionsAckTimestamp         time.Time `json:"enforcement_instructions_ack_timestamp,omitempty"`
	Status                                      string    `json:"status,omitempty"`
	NetworkEnforcementNode                      struct {
		Href string `json:"href,omitempty"`
	} `json:"network_enforcement_node,omitempty"`
	NetworkEndpoints []NetworkEndpoint
}

// NetworkEndpoint is the data structure for for a NEN Switch object that builds switch ACLs(JSON object too).
type NetworkEndpoint struct {
	Href   string `json:"href,omitempty"`
	Config struct {
		EndpointType      string `json:"endpoint_type,omitempty"`
		Name              string `json:"name,omitempty"`
		TrafficFlowID     string `json:"traffic_flow_id,omitempty"`
		WorkloadDiscovery bool   `json:"workload_discovery,omitempty"`
	} `json:"config,omitempty"`
	WorkloadDiscovery bool `json:"workload_discovery,omitempty"`
	NetworkDevice     struct {
		Href string `json:"href,omitempty"`
	} `json:"network_device,omitempty"`
	Workloads []struct {
		Href string `json:"href,omitempty"`
	} `json:"workloads,omitempty"`
	Status string `json:"status,omitempty"`
}

type NetDevice struct {
	Href string `json:"href"`
}

// NetworkDeviceACLRequest - Data structure for sending a port to the PCE to build ACL.
type NetworkDeviceACLRequest struct {
	ListNetworkDevices []NetDevice `json:"network_devices"`
}

// GetNetworkDeviceSlice -returns a slice of NetworkDevices(NEN siwtches) from the PCE as well as the Network Endpoints for each NetworkDevice.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// Currently Not putting async call if greater than 500.
func (p *PCE) GetNetworkDeviceSlice(queryParameters map[string]string) (api APIResponse, err error) {
	// Validate pStatus

	api, err = p.GetCollection("network_devices", false, queryParameters, &p.NetworkDeviceSlice)
	p.NetworkDevice = make(map[string]NetworkDevice)
	if err != nil {
		return api, err
	}

	//Cycle through the slide of devices to create a map of the devices using HREF and NAME as keys.
	for index, s := range p.NetworkDeviceSlice {
		var netendpoint []NetworkEndpoint
		api, err = p.GetCollection(strings.TrimPrefix(s.Href, fmt.Sprintf("/orgs/%d/", p.Org))+"/network_endpoints", false, map[string]string{}, &netendpoint)
		if err != nil {
			return api, err
		}
		p.NetworkDeviceSlice[index].NetworkEndpoints = netendpoint
		p.NetworkDevice[s.Href] = s
		p.NetworkDevice[s.Config.Name] = s
	}

	return api, err
}

// GetNetworkDevice - Get the NetworkDevice data to check if ACL is available
func (nd *NetworkDevice) GetNetworkDevice(p *PCE, tmpnd *NetworkDevice) (api APIResponse, err error) {
	// Validate pStatus

	api, err = p.GetHref(nd.Href, &tmpnd)
	if err != nil {
		return api, err
	}
	return api, err
}

// RequestNetworkDeviceAcl - will tell the NEN to create a new ACL file/json blob for that
// Network Device.   You will need to use another call to check if the job has finished.
func (nd *NetworkDevice) RequestNetworkDeviceACL(p *PCE) (api APIResponse, err error) {

	var requestNd = NetworkDeviceACLRequest{ListNetworkDevices: []NetDevice{{Href: nd.Href}}}

	var tmp interface{}
	api, err = p.Post("/network_devices/multi_enforcement_instructions_request", requestNd, &tmp)
	if err != nil {
		return api, err
	}

	return api, err
}
