package illumioapi

import (
	"fmt"
	"strings"
)

// PCE represents an Illumio PCE.
// All API calls are methods on the PCE.
// Each policy object is a map for lookups by various identifiers (href, name, etc.) so the length of the map will be some multiple of the total number of objects.
// There is also a slice for each object.
type PCE struct {
	FriendlyName                     string
	FQDN                             string
	Port                             int
	Org                              int
	User                             string
	Key                              string
	Proxy                            string
	DisableTLSChecking               bool
	Version                          Version
	Labels                           map[string]Label // Labels can be looked up by href or concatenated key and value (no character between key and value)
	LabelsSlice                      []Label
	LabelDimensions                  map[string]LabelDimension // LabelDimensions can be looked up by href or key
	LabelDimensionsSlice             []LabelDimension
	LabelGroups                      map[string]LabelGroup // Label Groups can be looked up by href or name
	LabelGroupsSlice                 []LabelGroup
	IPLists                          map[string]IPList // IP Lists can be looked up by href or name
	IPListsSlice                     []IPList
	Workloads                        map[string]Workload // Workloads can be looked up by href, hostname, name, or concatenated external dataset and reference (no character between)
	WorkloadsSlice                   []Workload
	VirtualServices                  map[string]VirtualService // VirtualServices can be looked up by href or name
	VirtualServicesSlice             []VirtualService
	VirtualServers                   map[string]VirtualServer // VirtualServers can be looked up by href or name
	VirtualServersSlice              []VirtualServer
	Services                         map[string]Service // Services can be looked up by href or name
	ServicesSlice                    []Service
	ConsumingSecurityPrincipals      map[string]ConsumingSecurityPrincipals // ConsumingSecurityPrincipals can be loooked up by href or name
	ConsumingSecurityPrincipalsSlice []ConsumingSecurityPrincipals
	RuleSets                         map[string]RuleSet // RuleSets can be looked up by href or name
	RuleSetsSlice                    []RuleSet
	VENs                             map[string]VEN // VENs can be looked up by href or name
	VENsSlice                        []VEN
	ContainerClusters                map[string]ContainerCluster
	ContainerClustersSlice           []ContainerCluster
	ContainerWorkloads               map[string]Workload
	ContainerWorkloadsSlice          []Workload
	ContainerWorkloadProfiles        map[string]ContainerWorkloadProfile
	ContainerWorkloadProfilesSlice   []ContainerWorkloadProfile
	EnforcementBoundaries            map[string]EnforcementBoundary
	EnforcementBoundariesSlice       []EnforcementBoundary
	PermissionsSlice                 []Permission
	Permissions                      map[string]Permission
	AuthSecurityPrincipalsSlices     []AuthSecurityPrincipal
	AuthSecurityPrincipals           map[string]AuthSecurityPrincipal
	Roles                            map[string]Role
	RolesSlice                       []Role
	NetworkDevice                    map[string]NetworkDevice
	NetworkDeviceSlice               []NetworkDevice
}

// LoadInput tells the p.Load method what objects to load
type LoadInput struct {
	ProvisionStatus             string // Must be draft or active. Blank value is draft
	LabelDimensions             bool
	Labels                      bool
	LabelGroups                 bool
	IPLists                     bool
	Workloads                   bool
	WorkloadsQueryParameters    map[string]string
	VirtualServices             bool
	VirtualServers              bool
	Services                    bool
	ConsumingSecurityPrincipals bool
	RuleSets                    bool
	VENs                        bool
	ContainerClusters           bool
	ContainerWorkloads          bool
	ContainerWorkloadProfiles   bool
	EnforcementBoundaries       bool
	Version                     bool
	AuthSecurityPrincipals      bool
	Permissions                 bool
	Roles                       bool
	NetworkDevice               bool
}

// Load gets the objects specified in the LoadInput
func (p *PCE) Load(l LoadInput, multiThread bool) (apiResps map[string]APIResponse, err error) {
	if multiThread {
		return p.loadMulti((l))
	}
	return p.loadSingle(l)
}

// loadMulti does multi-threaded GET APIs based on the LoadInput.
func (p *PCE) loadMulti(l LoadInput) (apiResps map[string]APIResponse, err error) {
	// Check provisionStatus
	provisionStatus := strings.ToLower(l.ProvisionStatus)
	if provisionStatus == "" {
		provisionStatus = "draft"
	}
	if provisionStatus != "draft" && provisionStatus != "active" {
		return apiResps, fmt.Errorf("provisionStatus must be draft or active")
	}

	type channelResp struct {
		api    APIResponse
		method string
		err    error
	}

	c := make(chan channelResp)

	apiResps = make(map[string]APIResponse)

	numAPICalls := 0

	// Labels
	if l.Labels {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetLabels(nil)
			c <- channelResp{api: apiResp, method: "GetLabels", err: err}
		}(p)
	}

	// Label Groups
	if l.LabelGroups {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetLabelGroups(nil, provisionStatus)
			c <- channelResp{api: apiResp, method: "GetLabelGroups", err: err}
		}(p)
	}

	// Label Dimensions
	if l.LabelDimensions {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetLabelDimensions(nil)
			c <- channelResp{api: apiResp, method: "GetLabelDimensions", err: err}
		}(p)
	}

	// IP Lists
	if l.IPLists {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetIPLists(nil, provisionStatus)
			c <- channelResp{api: apiResp, method: "GetIPLists", err: err}
		}(p)
	}

	// Workloads
	if l.Workloads {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetWklds(l.WorkloadsQueryParameters)
			c <- channelResp{api: apiResp, method: "GetWklds", err: err}
		}(p)
	}

	// Services
	if l.Services {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetServices(nil, provisionStatus)
			c <- channelResp{api: apiResp, method: "GetServices", err: err}
		}(p)
	}

	// Virtual Services
	if l.VirtualServices {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetVirtualServices(nil, provisionStatus)
			c <- channelResp{api: apiResp, method: "GetVirtualServices", err: err}
		}(p)
	}

	// Virtual Servers
	if l.VirtualServers {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetVirtualServers(nil, provisionStatus)
			c <- channelResp{api: apiResp, method: "GetVirtualServers", err: err}
		}(p)
	}

	// Rulesets
	if l.RuleSets {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetRulesets(nil, provisionStatus)
			c <- channelResp{api: apiResp, method: "GetRulesets", err: err}
		}(p)
	}

	// Consuming Security Principals
	if l.ConsumingSecurityPrincipals {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetADUserGroups(nil)
			c <- channelResp{api: apiResp, method: "GetADUserGroups", err: err}
		}(p)
	}

	// VENs
	if l.VENs {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetVens(nil)
			c <- channelResp{api: apiResp, method: "GetVens", err: err}
		}(p)
	}

	// Container Clusters
	if l.ContainerClusters {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetContainerClusters(nil)
			c <- channelResp{api: apiResp, method: "GetContainerClusters", err: err}
		}(p)
	}

	// Container Workloads
	if l.ContainerWorkloads {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetContainerWklds(nil)
			c <- channelResp{api: apiResp, method: "GetContainerWklds", err: err}
		}(p)
	}

	// Enforcement Boundaries
	if l.EnforcementBoundaries {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetEnforcementBoundaries(nil, provisionStatus)
			c <- channelResp{api: apiResp, method: "GetEnforcementBoundaries", err: err}
		}(p)
	}

	if l.AuthSecurityPrincipals {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetAuthSecurityPrincipal(nil)
			c <- channelResp{api: apiResp, method: "GetAuthSecurityPrincipal", err: err}
		}(p)
	}

	if l.Permissions {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetPermissions(nil)
			c <- channelResp{api: apiResp, method: "GetPermissions", err: err}
		}(p)
	}
	if l.Roles {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetRoles(nil)
			c <- channelResp{api: apiResp, method: "GetRoles", err: err}
		}(p)
	}
	if l.NetworkDevice {
		numAPICalls++
		go func(p *PCE) {
			apiResp, err := p.GetNetworkDeviceSlice(nil)
			c <- channelResp{api: apiResp, method: "GetNetworkDeviceSlide", err: err}
		}(p)
	}

	// Version
	if l.Version {
		numAPICalls++
		go func(p *PCE) {
			_, apiResp, err := p.GetVersion()
			c <- channelResp{api: apiResp, method: "GetVersion", err: err}
		}(p)
	}

	for i := 0; i <= numAPICalls-1; i++ {
		x := <-c
		apiResps[x.method] = x.api
		if x.err != nil {
			return nil, err
		}
	}

	return apiResps, nil
}

// loadSingle does single-threaded GET APIs based on the LoadInput.
func (p *PCE) loadSingle(l LoadInput) (map[string]APIResponse, error) {

	var err error
	var a APIResponse
	apiResps := make(map[string]APIResponse)

	// Check provisionStatus
	provisionStatus := strings.ToLower(l.ProvisionStatus)
	if provisionStatus == "" {
		provisionStatus = "draft"
	}
	if provisionStatus != "draft" && provisionStatus != "active" {
		return apiResps, fmt.Errorf("provisionStatus must be draft or active")
	}

	// Labels
	if l.Labels {
		a, err = p.GetLabels(nil)
		apiResps["GetLabels"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting labels - %s", err)
		}
	}

	// Label Groups
	if l.LabelGroups {
		a, err = p.GetLabelGroups(nil, provisionStatus)
		apiResps["GetLabelGroups"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting label groups - %s", err)
		}
	}

	// Label Dimensions
	if l.LabelDimensions {
		a, err = p.GetLabelDimensions(nil)
		apiResps["GetLabelDimensions"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting label dimensions - %s", err)
		}
	}

	// Get all IPLists
	if l.IPLists {
		a, err = p.GetIPLists(nil, provisionStatus)
		apiResps["GetIPLists"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting draft ip lists - %s", err)
		}
	}

	//  Workloads
	if l.Workloads {
		a, err = p.GetWklds(l.WorkloadsQueryParameters)
		apiResps["GetWklds"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting workloads - %s", err)
		}
	}

	// Services
	if l.Services {
		a, err = p.GetServices(nil, provisionStatus)
		apiResps["GetServices"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all services - %s", err)
		}
	}

	// Virtual services
	if l.VirtualServices {
		a, err = p.GetVirtualServices(nil, provisionStatus)
		apiResps["GetVirtualServices"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting virtual services - %s", err)
		}
	}

	// VirtualServers
	if l.VirtualServers {
		a, err = p.GetVirtualServers(nil, provisionStatus)
		apiResps["GetVirtualServers"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all virtual servers - %s", err)
		}

	}

	// Rulesets
	if l.RuleSets {
		a, err = p.GetRulesets(nil, provisionStatus)
		apiResps["GetRulesets"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all rulesets - %s", err)
		}
	}

	// Consuming Security Principals
	if l.ConsumingSecurityPrincipals {
		a, err = p.GetADUserGroups(nil)
		apiResps["GetADUserGroups"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all consuming security principals - %s", err)
		}
	}

	// Get VENs
	if l.VENs {
		a, err = p.GetVens(nil)
		apiResps["GetAllVens"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all vens - %s", err)
		}
	}

	// Container Clusters
	if l.ContainerClusters {
		a, err = p.GetContainerClusters(nil)
		apiResps["GetAllContainerClusters"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all container clusters - %s", err)
		}
	}

	// Container Workloads
	if l.ContainerWorkloads {
		a, err = p.GetContainerWklds(nil)
		apiResps["GetAllContainerWorkloads"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all container workloads - %s", err)
		}
	}

	// Enforcement Boundaries
	if l.EnforcementBoundaries {
		a, err = p.GetEnforcementBoundaries(nil, provisionStatus)
		apiResps["GetAllEnforcementBoundaries"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all enforcement boundaries - %s", err)
		}
	}

	if l.Roles {
		a, err = p.GetRoles(nil)
		apiResps["GetRoles"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all roles - %s", err)
		}
	}
	if l.Permissions {
		a, err = p.GetPermissions(nil)
		apiResps["GetPermissions"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all permissions - %s", err)
		}
	}
	if l.AuthSecurityPrincipals {
		a, err = p.GetAuthSecurityPrincipal(nil)
		apiResps["GetAuthSecurityPrincipal"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting all auth sec principals - %s", err)
		}
	}

	// Version
	if l.Version {
		_, a, err = p.GetVersion()
		apiResps["GetVersion"] = a
		if err != nil {
			return apiResps, fmt.Errorf("getting version - %s", err)
		}
	}

	return apiResps, nil
}

// FindObject takes an href and returns what it is and the name
func (p *PCE) FindObject(href string) (key, name string, err error) {

	// IPLists
	if strings.Contains(href, "/ip_lists/") {
		return "iplist", p.IPLists[href].Name, nil
	}
	// Labels
	if strings.Contains(href, "/labels/") {
		return fmt.Sprintf("%s_label", p.Labels[href].Key), p.Labels[href].Value, nil
	}
	// Label Groups
	if strings.Contains(href, "/label_groups/") {
		return fmt.Sprintf("%s_label_group", p.LabelGroups[href].Key), p.LabelGroups[href].Name, nil
	}
	// Virtual Services
	if strings.Contains(href, "/virtual_services/") {
		return "virtual_service", p.VirtualServices[href].Name, nil
	}
	// Workloads
	if strings.Contains(href, "/workloads/") {
		if PtrToVal(p.Workloads[href].Hostname) != "" {
			return "workload", *p.Workloads[href].Hostname, nil
		}
		return "workload", PtrToVal(p.Workloads[href].Name), nil
	}

	return "nil", "nil", fmt.Errorf("object not found")
}

// ParseObjectType takes an href and returns one of the following options: iplist, label, label_group, virtual_service, workload, or unknown.
func ParseObjectType(href string) string {
	// IPLists
	if strings.Contains(href, "/ip_lists/") {
		return "iplist"
	}
	// Labels
	if strings.Contains(href, "/labels/") {
		return "label"
	}
	// Label Groups
	if strings.Contains(href, "/label_groups/") {
		return "label_group"
	}
	// Virtual Services
	if strings.Contains(href, "/virtual_services/") {
		return "virtual_service"
	}
	// Workloads
	if strings.Contains(href, "/workloads/") {
		return "workload"
	}
	return "unknown"

}
