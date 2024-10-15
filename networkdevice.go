package illumioapi

import (
	"fmt"
	"strings"
	"time"
)

type NetworkEndpointRequest struct {
	Config struct {
		EndpointType      string `json:"endpoint_type"`
		Name              string `json:"name"`
		TrafficFlowID     string `json:"traffic_flow_id,omitempty"`
		WorkloadDiscovery bool   `json:"workload_discovery,omitempty"`
	} `json:"config"`
	Workloads []struct {
		Href string `json:"href,omitempty"`
	} `json:"workloads"`
}

type NetworkDeviceRequest struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	DeviceType   string `json:"device_type"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	IPAddress    string `json:"ip_address"`
	// Credentials  struct {
	// 	Type     string `json:"type"`
	// 	Port     int    `json:"port"`
	// 	Username string `json:"username"`
	// 	Password string `json:"password"`
	// } `json:"credentials"`
}

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

// NetworkEnforcementNode - Data Structure for the NEN and all its capabilities.
type NetworkEnforcementNode struct {
	Href              string          `json:"href"`
	Hostname          string          `json:"hostname"`
	PublicIP          string          `json:"public_ip"`
	Name              string          `json:"name"`
	SoftwareVersion   string          `json:"software_version"`
	LastStatusAt      time.Time       `json:"last_status_at"`
	UptimeSeconds     int             `json:"uptime_seconds"`
	NetworkDevices    []NetworkDevice `json:"network_devices"`
	NetworkDevicesMap map[string]NetworkDevice
	SupportedDevices  []struct {
		DeviceType    string `json:"device_type"`
		Manufacturers []struct {
			Manufacturer string `json:"manufacturer"`
			Models       []struct {
				Model string `json:"model"`
			} `json:"models"`
		} `json:"manufacturers"`
	} `json:"supported_devices"`
	TargetPceFqdn any `json:"target_pce_fqdn"`
	ActivePceFqdn any `json:"active_pce_fqdn"`
	Conditions    []struct {
		FirstReportedTimestamp time.Time `json:"first_reported_timestamp"`
		LatestEvent            struct {
			NotificationType string `json:"notification_type"`
			Severity         string `json:"severity"`
			Href             string `json:"href"`
			Info             struct {
				NetworkEnforcementNode struct {
					Href     string `json:"href"`
					Name     string `json:"name"`
					Hostname string `json:"hostname"`
				} `json:"network_enforcement_node"`
			} `json:"info"`
			Timestamp time.Time `json:"timestamp"`
		} `json:"latest_event"`
	} `json:"conditions"`
}

// GetNetworkEnforcementNodeSlice - Get a list of all the NENs configured on the system.
func (p *PCE) GetNetworkEnforcementNodeSlice(queryParameters map[string]string) (api APIResponse, err error) {

	p.NetworkEnforcementNode = make(map[string]NetworkEnforcementNode)
	api, err = p.GetCollection("network_enforcement_nodes", false, queryParameters, &p.NetworkEnforcementNodeSlice)
	if err != nil {
		return api, err
	}

	//Cycle through the slide of devices to create a map of the devices using HREF and NAME as keys.
	for index, nen := range p.NetworkEnforcementNodeSlice {
		var netdevice NetworkDevice
		var netendpoint []NetworkEndpoint

		//make sure to initialize the NetworkDeviceMap.
		p.NetworkEnforcementNodeSlice[index].NetworkDevicesMap = make(map[string]NetworkDevice)
		for index2, nd := range nen.NetworkDevices {
			//Get all the data for the NetworkDevices....NetworkEnforcementNode only provides HREF
			p.GetNetworkDevice(nd.Href, &netdevice)

			//Get the endpoints for the NetworkDevice and add to NetworkDevice
			p.GetNetworkEndpoint(nd.Href, &netendpoint)
			netdevice.NetworkEndpoints = netendpoint

			//Overwrite NEN's NetworkDevices and create a map.
			p.NetworkEnforcementNodeSlice[index].NetworkDevices[index2] = netdevice
			p.NetworkEnforcementNodeSlice[index].NetworkDevicesMap[netdevice.Href] = netdevice
			p.NetworkEnforcementNodeSlice[index].NetworkDevicesMap[netdevice.Config.Name] = netdevice

		}

		p.NetworkEnforcementNode[nen.Href] = p.NetworkEnforcementNodeSlice[index]
		p.NetworkEnforcementNode[nen.Hostname] = p.NetworkEnforcementNodeSlice[index]
	}

	return api, err
}

// GetNetworkEndpoint - Get the NetworkDevice data to check if ACL is available
func (p *PCE) GetNetworkEndpoint(href string, tmpne *[]NetworkEndpoint) (api APIResponse, err error) {
	// Validate pStatus

	api, err = p.GetHref(href+"/network_endpoints", &tmpne)
	if err != nil {
		return api, err
	}
	return api, err
}

// GetNetworkDevice - Get the NetworkDevice data to check if ACL is available
func (p *PCE) GetNetworkDevice(href string, tmpnd *NetworkDevice) (api APIResponse, err error) {
	// Validate pStatus

	api, err = p.GetHref(href, &tmpnd)
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

// AddNetworkDevice - Adds a Switch on the NEN so UMWL can be placed on it to build ACLs for the UMWL
func (nen *NetworkEnforcementNode) AddNetworkDevice(p *PCE, ndAdd NetworkDeviceRequest, tmpnd *NetworkDevice) (api APIResponse, err error) {

	api, err = p.Post(strings.TrimPrefix(nen.Href, fmt.Sprintf("/orgs/%d/", p.Org))+"/network_devices", ndAdd, &tmpnd)
	if err != nil {
		return api, err
	}

	return api, err
}

// AddNetworkEndpoint - Adds different UMWL onto a NEN Switch so that ACLs can be created for that UMWL.
func (nd *NetworkDevice) AddNetworkEndpoint(p *PCE, neAdd *NetworkEndpointRequest) (api APIResponse, err error) {

	var tmpne NetworkEndpoint
	api, err = p.Post(strings.TrimPrefix(nd.Href, fmt.Sprintf("/orgs/%d/", p.Org))+"/network_endpoints", neAdd, &tmpne)
	if err != nil {
		return api, err
	}

	return api, err
}
