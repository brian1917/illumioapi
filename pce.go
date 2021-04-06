package illumioapi

import (
	"fmt"
	"strings"
)

// PCE represents an Illumio PCE and the necessary info to authenticate. The policy objects are maps for lookups. ]
// Each map will have multiple look up keys so the length of the map will be larger than the total objects.
// For example, each label will be in the map for an HREF and a key value.
// Policy objects should be called by their corresponding PCE method if you need to iterate or count them (e.g., pce.GetAllLabels)
type PCE struct {
	FQDN                        string
	Port                        int
	Org                         int
	User                        string
	Key                         string
	DisableTLSChecking          bool
	Labels                      map[string]Label                       // Labels can be looked up by href or key+value (no character between key and value)
	LabelGroups                 map[string]LabelGroup                  // Label Groups can be looked up by href or name
	IPLists                     map[string]IPList                      // IP Lists can be looked up by href or name
	Workloads                   map[string]Workload                    // Workloads can be looked up by href, hostname, or names
	VirtualServices             map[string]VirtualService              // VirtualServices can be looked up by href or name
	VirtualServers              map[string]VirtualServer               // VirtualServers can be looked up by href or name
	Services                    map[string]Service                     // Services can be looked up by href or name
	ServicesSlice               []Service                              // All services stored in a slice
	ConsumingSecurityPrincipals map[string]ConsumingSecurityPrincipals // ConsumingSecurityPrincipals can be loooked up by href or name
	RuleSets                    map[string]RuleSet                     // RuleSets can be looked up by href or name
}

// LoadInput tells the p.Load method what objects to load
type LoadInput struct {
	ProvisionStatus             string // Must be draft or active. Blank value is draft
	Labels                      bool
	LabelGroups                 bool
	IPLists                     bool
	Workloads                   bool
	VirtualServices             bool
	VirtualServers              bool
	Services                    bool
	ConsumingSecurityPrincipals bool
	RuleSets                    bool
}

// Load fills the PCE object maps
// provisionStatus must be "draft" or "active"
func (p *PCE) Load(l LoadInput) error {

	var err error

	// Check provisionStatus
	provisionStatus := strings.ToLower(l.ProvisionStatus)
	if provisionStatus == "" {
		provisionStatus = "draft"
	}
	if provisionStatus != "draft" && provisionStatus != "active" {
		return fmt.Errorf("provisionStatus must be draft or active")
	}

	// Get Label maps
	if l.Labels {
		labels, _, err := p.GetAllLabels()
		if err != nil {
			return fmt.Errorf("getting labels - %s", err)
		}
		p.Labels = make(map[string]Label)
		for _, l := range labels {
			p.Labels[l.Href] = l
			p.Labels[l.Key+l.Value] = l
		}
	}

	// Get all label groups
	if l.LabelGroups {
		lgs, _, err := p.GetAllLabelGroups(provisionStatus)
		if err != nil {
			return fmt.Errorf("getting label groups - %s", err)
		}
		p.LabelGroups = make(map[string]LabelGroup)
		for _, lg := range lgs {
			p.LabelGroups[lg.Href] = lg
			p.LabelGroups[lg.Name] = lg
		}
	}

	// Get all IPLists
	if l.IPLists {
		ipls, _, err := p.getAllIPLists(provisionStatus)
		if err != nil {
			return fmt.Errorf("getting draft ip lists - %s", err)
		}
		p.IPLists = make(map[string]IPList)
		for _, ipl := range ipls {
			p.IPLists[ipl.Href] = ipl
			p.IPLists[ipl.Name] = ipl
		}
	}

	// Get all Workloads
	if l.Workloads {
		wklds, _, err := p.GetAllWorkloads()
		if err != nil {
			return fmt.Errorf("getting workloads - %s", err)
		}
		p.Workloads = make(map[string]Workload)
		for _, w := range wklds {
			p.Workloads[w.Href] = w
			p.Workloads[w.Hostname] = w
			p.Workloads[w.Name] = w
		}
	}

	// Virtual services
	if l.VirtualServices {
		virtualServices, _, err := p.GetAllVirtualServices(nil, provisionStatus)
		if err != nil {
			return fmt.Errorf("getting virtual services - %s", err)
		}
		p.VirtualServices = make(map[string]VirtualService)
		for _, vs := range virtualServices {
			p.VirtualServices[vs.Href] = vs
			p.VirtualServices[vs.Name] = vs
		}
	}

	// Services
	if l.Services {
		p.ServicesSlice, _, err = p.GetAllServices(provisionStatus)
		if err != nil {
			return fmt.Errorf("getting all services - %s", err)
		}
		p.Services = make(map[string]Service)
		for _, s := range p.ServicesSlice {
			p.Services[s.Href] = s
			p.Services[s.Name] = s
		}
	}

	// VirtualServers
	if l.VirtualServers {
		virtualServers, _, err := p.GetAllVirtualServers(provisionStatus)
		if err != nil {
			return fmt.Errorf("getting all virtual servers - %s", err)
		}
		p.VirtualServers = make(map[string]VirtualServer)
		for _, v := range virtualServers {
			p.VirtualServers[v.Href] = v
			p.VirtualServers[v.Name] = v
		}
	}

	// Rulesets
	if l.RuleSets {
		rulesets, _, err := p.GetAllRuleSets(provisionStatus)
		if err != nil {
			return fmt.Errorf("getting all rulesets - %s", err)
		}
		p.RuleSets = make(map[string]RuleSet)
		for _, rs := range rulesets {
			p.RuleSets[rs.Href] = rs
			p.RuleSets[rs.Name] = rs
		}
	}

	// Consuming Security Principals
	if l.ConsumingSecurityPrincipals {
		cps, _, err := p.GetAllADUserGroups()
		if err != nil {
			return fmt.Errorf("getting all consuming security principals - %s", err)
		}
		p.ConsumingSecurityPrincipals = make(map[string]ConsumingSecurityPrincipals)
		for _, cp := range cps {
			p.ConsumingSecurityPrincipals[cp.Href] = cp
			p.ConsumingSecurityPrincipals[cp.Name] = cp
		}
	}

	return nil
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
		if p.Workloads[href].Hostname != "" {
			return "workload", p.Workloads[href].Hostname, nil
		}
		return "workload", p.Workloads[href].Name, nil
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
