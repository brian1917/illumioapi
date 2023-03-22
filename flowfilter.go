package illumioapi

// A flowfilter is a collector filter
type FlowFilter struct {
	Href         string  `json:"href,omitempty"`
	Action       string  `json:"action,omitempty"`       // drop or aggregate
	Transmission string  `json:"transmission,omitempty"` // broadcast, multicast, unicast
	Target       *Target `json:"target,omitempty"`
}

// Target is part of the collector flow filter
type Target struct {
	Proto   int    `json:"proto,omitempty"`
	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DestIP  string `json:"dst_ip,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
}

// CreateLabel creates a new Label in the PCE.
func (p *PCE) CreateFlowFilter(flowFilter FlowFilter) (createdFlowFilter FlowFilter, api APIResponse, err error) {
	api, err = p.Post("settings/traffic_collector", &flowFilter, &createdFlowFilter)
	return createdFlowFilter, api, err
}
