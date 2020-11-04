package illumioapi

import (
	"fmt"
	"strings"
)

// PCE represents an Illumio PCE and the necessary info to authenticate
type PCE struct {
	FQDN               string
	Port               int
	Org                int
	User               string
	Key                string
	DisableTLSChecking bool
	LabelMapKV         map[string]Label
	LabelGroupMapName  map[string]LabelGroup
	LabelMapH          map[string]Label
	LabelGroupMapH     map[string]LabelGroup
	IPListMapH         map[string]IPList
	WorkloadMapH       map[string]Workload
	VirtualServiceMapH map[string]VirtualService
	VirtualServerMapH  map[string]VirtualServer
	ServiceMapH        map[string]Service
}

// Load fills the PCE object maps
// provisionStatus must be "draft" or "active"
func (p *PCE) Load(provisionStatus string) error {

	// Check provisionStatus
	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "draft" && provisionStatus != "active" {
		return fmt.Errorf("provisionStatus must be draft or active")
	}

	// Get Label maps
	_, err := p.GetLabelMaps()
	if err != nil {
		return fmt.Errorf("getting label maps - %s", err)
	}

	// Get all label groups
	lgs, _, err := p.GetAllLabelGroups(provisionStatus)
	if err != nil {
		return fmt.Errorf("getting label groups - %s", err)
	}
	p.LabelGroupMapH = make(map[string]LabelGroup)
	for _, lg := range lgs {
		p.LabelGroupMapH[lg.Href] = lg
	}

	// Get all IPLists
	ipls, _, err := p.getAllIPLists(provisionStatus)
	if err != nil {
		return fmt.Errorf("getting draft ip lists - %s", err)
	}
	p.IPListMapH = make(map[string]IPList)
	for _, ipl := range ipls {
		p.IPListMapH[ipl.Href] = ipl
	}

	// Get all Workloads
	wklds, _, err := p.GetAllWorkloads()
	if err != nil {
		return fmt.Errorf("getting workloads - %s", err)
	}
	p.WorkloadMapH = make(map[string]Workload)
	for _, w := range wklds {
		p.WorkloadMapH[w.Href] = w
	}

	// Virtual services
	virtualServices, _, err := p.GetAllVirtualServices(nil, provisionStatus)
	if err != nil {
		return fmt.Errorf("getting virtual services - %s", err)
	}
	p.VirtualServiceMapH = make(map[string]VirtualService)
	for _, vs := range virtualServices {
		p.VirtualServiceMapH[vs.Href] = vs
	}

	// Services
	services, _, err := p.GetAllServices(provisionStatus)
	if err != nil {
		return fmt.Errorf("getting all services - %s", err)
	}
	p.ServiceMapH = make(map[string]Service)
	for _, s := range services {
		p.ServiceMapH[s.Href] = s
	}

	// VirtualServers
	virtualServers, _, err := p.GetAllVirtualServers(provisionStatus)
	if err != nil {
		return fmt.Errorf("getting all virtual servers - %s", err)
	}
	p.VirtualServerMapH = make(map[string]VirtualServer)
	for _, v := range virtualServers {
		p.VirtualServerMapH[v.Href] = v
	}

	return nil
}

// FindObject takes an href and returns what it is and the name
func (p *PCE) FindObject(href string) (key, name string, err error) {

	// IPLists
	if strings.Contains(href, "/ip_lists/") {
		return "iplist", p.IPListMapH[href].Name, nil
	}
	// Labels
	if strings.Contains(href, "/labels/") {
		return fmt.Sprintf("%s_label", p.LabelMapH[href].Key), p.LabelMapH[href].Value, nil
	}
	// Label Groups
	if strings.Contains(href, "/label_groups/") {
		return fmt.Sprintf("%s_label_group", p.LabelGroupMapH[href].Key), p.LabelGroupMapH[href].Name, nil
	}
	// Virtual Services
	if strings.Contains(href, "/virtual_services/") {
		return "virtual_service", p.VirtualServiceMapH[href].Name, nil
	}
	// Workloads
	if strings.Contains(href, "/workloads/") {
		if p.WorkloadMapH[href].Hostname != "" {
			return "workload", p.WorkloadMapH[href].Hostname, nil
		}
		return "workload", p.WorkloadMapH[href].Name, nil
	}

	return "nil", "nil", fmt.Errorf("object not found")
}
