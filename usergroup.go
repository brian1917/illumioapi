package illumioapi

// ConsumingSecurityPrincipals are AD user groups
type ConsumingSecurityPrincipals struct {
	Deleted       bool   `json:"deleted,omitempty"`
	Description   string `json:"description,omitempty"`
	Href          string `json:"href,omitempty"`
	Name          string `json:"name,omitempty"`
	SID           string `json:"sid,omitempty"`
	UsedByRuleSet bool   `json:"used_by_ruleset,omitempty"`
}

// GetADUserGroups returns a slice of AD user groups from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetADUserGroups(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("security_principals", false, queryParameters, &p.ConsumingSecurityPrincipalsSlice)
	if len(p.ConsumingSecurityPrincipalsSlice) >= 500 {
		p.ConsumingSecurityPrincipalsSlice = nil
		api, err = p.GetCollection("security_principals", true, queryParameters, &p.ConsumingSecurityPrincipalsSlice)
	}
	p.ConsumingSecurityPrincipals = make(map[string]ConsumingSecurityPrincipals)
	for _, cp := range p.ConsumingSecurityPrincipalsSlice {
		p.ConsumingSecurityPrincipals[cp.Href] = cp
		p.ConsumingSecurityPrincipals[cp.Name] = cp
		p.ConsumingSecurityPrincipals[cp.SID] = cp
	}
	return api, err
}

// CreateADUserGroup creates a user group policy object in the PCE
func (p *PCE) CreateADUserGroup(group ConsumingSecurityPrincipals) (createdGroup ConsumingSecurityPrincipals, api APIResponse, err error) {
	api, err = p.Post("security_principals", &group, &createdGroup)
	return createdGroup, api, err
}

// UpdateADUserGroup updates an existing AD user group in the PCE.
// The provided ad user group must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateADUserGroup(group ConsumingSecurityPrincipals) (APIResponse, error) {
	// Create a new ad user group with just the fields that should be updated and the href
	g := ConsumingSecurityPrincipals{
		Href:        group.Href,
		Description: group.Description,
		Name:        group.Name,
	}
	api, err := p.Put(&g)
	return api, err
}
