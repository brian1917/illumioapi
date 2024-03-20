package illumioapi

// Href is used for CreatedBy, UpdatedBy, etc. that require just an href.
type Href struct {
	Href string `json:"href"`
}

// ConsumerOrProvider is used by rules and enforcement boundaries.
type ConsumerOrProvider struct {
	Actors         *string         `json:"actors,omitempty"`
	IPList         *IPList         `json:"ip_list,omitempty"`
	Label          *Label          `json:"label,omitempty"`
	LabelGroup     *LabelGroup     `json:"label_group,omitempty"`
	VirtualServer  *VirtualServer  `json:"virtual_server,omitempty"`
	VirtualService *VirtualService `json:"virtual_service,omitempty"`
	Workload       *Workload       `json:"workload,omitempty"`
	Exclusion      *bool           `json:"exclusion,omitempty"`
}

// Actors are part of consumer or providers for rules and boundaries.
type Actors struct {
	Actors     *string     `json:"actors,omitempty"`
	Label      *Label      `json:"label,omitempty"`
	LabelGroup *LabelGroup `json:"label_group,omitempty"`
	Workload   *Workload   `json:"workload,omitempty"`
}
