package illumioapi

// An EnforcementBoundary is part of Illumio policy to dicated where policy is enforced.
type EnforcementBoundary struct {
	Href            string                `json:"href,omitempty"`
	Name            string                `json:"name,omitempty"`
	Providers       *[]ConsumerOrProvider `json:"providers,omitempty"`
	Consumers       *[]ConsumerOrProvider `json:"consumers,omitempty"`
	IngressServices *[]IngressServices    `json:"ingress_services,omitempty"`
	Enabled         *bool                 `json:"enabled,omitempty"`
	NetworkType     string                `json:"network_type,omitempty"` //  ["brn", "non_brn", "all"]
	CreatedAt       string                `json:"created_at,omitempty"`
	CreatedBy       *Href                 `json:"created_by,omitempty"`
	DeletedAt       string                `json:"deleted_at,omitempty"`
	DeletedBy       *Href                 `json:"deleted_by,omitempty"`
	UpdateType      string                `json:"update_type,omitempty"`
	UpdatedAt       string                `json:"updated_at,omitempty"`
	UpdatedBy       *Href                 `json:"updated_by,omitempty"`
}

// GetEnforcementBoundaries returns a slice of enforcement boundaries from the PCE.
// pStatus must be "draft" or "active".
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetEnforcementBoundaries(queryParameters map[string]string, pStatus string) (api APIResponse, err error) {
	api, err = p.GetCollection("sec_policy/"+pStatus+"/enforcement_boundaries", false, queryParameters, &p.EnforcementBoundariesSlice)
	if len(p.EnforcementBoundariesSlice) >= 500 {
		p.EnforcementBoundariesSlice = nil
		api, err = p.GetCollection("sec_policy/"+pStatus+"/enforcement_boundaries", true, queryParameters, &p.EnforcementBoundariesSlice)
	}
	p.EnforcementBoundaries = map[string]EnforcementBoundary{}
	for _, eb := range p.EnforcementBoundariesSlice {
		p.EnforcementBoundaries[eb.Name] = eb
		p.EnforcementBoundaries[eb.Href] = eb
	}
	return api, err
}

// GetEnforcementBoundaryByHref returns the enforcement boundary with the specified HREF
func (p *PCE) GetEnforcementBoundaryByHref(href string) (eb EnforcementBoundary, api APIResponse, err error) {
	api, err = p.GetHref(href, &eb)
	return eb, api, err
}

// CreateEnforcementBoundary creates a new enforcement boundary in the Illumio PCE
func (p *PCE) CreateEnforcementBoundary(eb EnforcementBoundary) (createdEB EnforcementBoundary, api APIResponse, err error) {
	api, err = p.Post("/sec_policy/draft/enforcement_boundaries", &eb, &createdEB)
	return createdEB, api, err
}

// UpdateEnforcementBoundary updates an existing enforcement boundary in the PCE.
// The provided enforcement boundary object must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateEnforcementBoundary(eb EnforcementBoundary) (APIResponse, error) {
	eb.CreatedAt = ""
	eb.CreatedBy = nil
	eb.UpdateType = ""
	eb.UpdatedAt = ""
	eb.UpdatedBy = nil
	eb.DeletedAt = ""
	eb.DeletedBy = nil

	return p.Put(&eb)
}

// DeleteEnforcementBoundary removes an enforcement boundary from the PCE.
// The provided enforcement boundary object must include an Href.
func (p *PCE) DeleteEnforcementBoundary(eb EnforcementBoundary) (APIResponse, error) {
	return p.DeleteHref(eb.Href)
}
