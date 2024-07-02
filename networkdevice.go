package illumioapi

import "time"

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
	NetworkEndpoints []struct {
		Href string `json:"href,omitempty"`
	} `json:"network_endpoints,omitempty"`
}

// GetNetworkEnforcementNodes returns a slice of NetworkEnforcementNodes from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// Not putting async call if greater than 500.
func (p *PCE) GetNetworkDeviceSlide(queryParameters map[string]string) (api APIResponse, err error) {
	// Validate pStatus

	api, err = p.GetCollection("network_enforcement_nodes", false, queryParameters, &p.NetworkDeviceSlice)
	p.NetworkDevice = make(map[string]NetworkDevice)
	for _, s := range p.NetworkDeviceSlice {
		p.NetworkDevice[s.Href] = s
	}
	return api, err
}
