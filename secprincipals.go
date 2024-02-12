package illumioapi

type Permission struct {
	Href                  string                 `json:"href,omitempty"`
	Role                  *Role                  `json:"role,omitempty"`
	Scope                 *[]Scopes              `json:"scope,omitempty"`
	AuthSecurityPrincipal *AuthSecurityPrincipal `json:"auth_security_principal,omitempty"`
}
type Role struct {
	Href string `json:"href,omitempty"`
}

type AuthSecurityPrincipal struct {
	Href        string `json:"href,omitempty"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Type        string `json:"type,omitempty"`
}

// Avaiable roles
var AvailableRoles = map[string]bool{
	"read_only":                 true,
	"admin":                     true,
	"owner":                     true,
	"ruleset_manager":           true,
	"ruleset_provisioner":       true,
	"global_object_provisioner": true,
	"limited_ruleset_manager":   true,
	"workload_manager":          true,
	"ruleset_viewer":            true,
}

func AvailableRolesSlice() (roles []string) {
	for role := range AvailableRoles {
		roles = append(roles, role)
	}
	return roles
}

// GetPermissions returns a slice of permissions from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetPermissions(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("permissions", false, queryParameters, &p.PermissionsSlice)
	if len(p.PermissionsSlice) >= 500 {
		p.PermissionsSlice = nil
		api, err = p.GetCollection("permissions", true, queryParameters, &p.PermissionsSlice)
	}
	p.Permissions = make(map[string]Permission)
	for _, permission := range p.PermissionsSlice {
		p.Permissions[permission.Href] = permission
	}
	return api, err
}

// GetRoles returns a slice of roles from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetRoles(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("roles", false, queryParameters, &p.RolesSlice)
	if len(p.RolesSlice) >= 500 {
		p.RolesSlice = nil
		api, err = p.GetCollection("roles", true, queryParameters, &p.RolesSlice)
	}
	p.Roles = make(map[string]Role)
	for _, role := range p.RolesSlice {
		p.Roles[role.Href] = role
	}
	return api, err
}

// GetAuthSecurityPrincipalermissions returns a slice of AuthSecurityPrincipals from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetAuthSecurityPrincipal(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("auth_security_principals", false, queryParameters, &p.AuthSecurityPrincipalsSlices)
	if len(p.AuthSecurityPrincipalsSlices) >= 500 {
		p.AuthSecurityPrincipalsSlices = nil
		api, err = p.GetCollection("auth_security_principals", true, queryParameters, &p.AuthSecurityPrincipalsSlices)
	}
	p.AuthSecurityPrincipals = make(map[string]AuthSecurityPrincipal)
	for _, a := range p.AuthSecurityPrincipalsSlices {
		p.AuthSecurityPrincipals[a.Href] = a
		p.AuthSecurityPrincipals[a.Name] = a
	}
	return api, err
}

// CreateAuthSecurityPrincipal creates a new authorized security principal in the PCE.
func (p *PCE) CreateAuthSecurityPrincipal(authSecPrincipal AuthSecurityPrincipal) (createdAuthSecPrincipal AuthSecurityPrincipal, api APIResponse, err error) {
	api, err = p.Post("auth_security_principals", &authSecPrincipal, &createdAuthSecPrincipal)
	return createdAuthSecPrincipal, api, err
}

// CreatePermission creates a new authorized security principal in the PCE.
func (p *PCE) CreatePermission(permission Permission) (createdPermission Permission, api APIResponse, err error) {
	api, err = p.Post("permissions", &permission, &createdPermission)
	return createdPermission, api, err
}

// UpdatePermission updates an existing permission in the PCE.
// The provided permission must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdatePermission(permission Permission) (APIResponse, error) {
	// Create a new permission with just the fields that should be updated and the href
	updatedPermission := Permission{
		Href:                  permission.Href,
		Scope:                 permission.Scope,
		AuthSecurityPrincipal: permission.AuthSecurityPrincipal,
	}
	api, err := p.Put(&updatedPermission)
	return api, err
}
