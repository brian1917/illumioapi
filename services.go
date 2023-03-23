package illumioapi

import (
	"fmt"
	"strings"
)

// Service represent a service in the PCE
type Service struct {
	Href                  string            `json:"href,omitempty"`
	Name                  string            `json:"name"`
	Description           string            `json:"description,omitempty"`
	ProcessName           string            `json:"process_name,omitempty"`
	ServicePorts          *[]ServicePort    `json:"service_ports,omitempty"`
	WindowsServices       *[]WindowsService `json:"windows_services,omitempty"`
	ExternalDataReference *string           `json:"external_data_reference,omitempty"`
	ExternalDataSet       *string           `json:"external_data_set,omitempty"`
	UpdateType            string            `json:"update_type,omitempty"`
	CreatedAt             string            `json:"created_at,omitempty"`
	CreatedBy             *Href             `json:"created_by,omitempty"`
	DeletedAt             string            `json:"deleted_at,omitempty"`
	DeletedBy             *Href             `json:"deleted_by,omitempty"`
	UpdatedAt             string            `json:"updated_at,omitempty"`
	UpdatedBy             *Href             `json:"updated_by,omitempty"`
}

// ServicePort represent port and protocol information for a non-Windows service
type ServicePort struct {
	IcmpCode int `json:"icmp_code,omitempty"`
	IcmpType int `json:"icmp_type,omitempty"`
	ID       int `json:"id,omitempty"`
	Port     int `json:"port,omitempty"`
	Protocol int `json:"proto,omitempty"`
	ToPort   int `json:"to_port,omitempty"`
}

// WindowsService represents port, protocol, and process information for a Windows service
type WindowsService struct {
	IcmpCode    int    `json:"icmp_code,omitempty"`
	IcmpType    int    `json:"icmp_type,omitempty"`
	Port        int    `json:"port,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Protocol    int    `json:"proto,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ToPort      int    `json:"to_port,omitempty"`
}

// GetServices returns a slice of IP lists from the PCE. pStatus must be "draft" or "active".
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetServices(queryParameters map[string]string, pStatus string) (api APIResponse, err error) {
	// Validate pStatus
	pStatus = strings.ToLower(pStatus)
	if pStatus != "active" && pStatus != "draft" {
		return api, fmt.Errorf("invalid pStatus")
	}
	api, err = p.GetCollection("/sec_policy/"+pStatus+"/services", false, queryParameters, &p.ServicesSlice)
	if len(p.ServicesSlice) >= 500 {
		p.ServicesSlice = nil
		api, err = p.GetCollection("/sec_policy/"+pStatus+"/services", true, queryParameters, &p.ServicesSlice)
	}
	p.Services = make(map[string]Service)
	for _, s := range p.ServicesSlice {
		p.Services[s.Href] = s
		p.Services[s.Name] = s
	}
	return api, err
}

// CreateService creates a new service in the PCE.
func (p *PCE) CreateService(service Service) (createdService Service, api APIResponse, err error) {
	api, err = p.Post("sec_policy/draft/services", &service, &createdService)
	return createdService, api, err
}

// UpdateService updates an existing service object in the Illumio PCE
func (p *PCE) UpdateService(service Service) (APIResponse, error) {
	service.CreatedAt = ""
	service.CreatedBy = nil
	service.UpdateType = ""
	service.UpdatedAt = ""
	service.UpdatedBy = nil

	api, err := p.Put(&service)
	return api, err
}

// ParseService returns a slice of WindowsServices and ServicePorts from an Illumio service object
func (s *Service) ParseService() (windowsServices, servicePorts []string) {

	// Create a string for Windows Services
	for _, ws := range PtrToVal(s.WindowsServices) {
		var svcSlice []string
		if ws.Port != 0 && ws.Protocol != 0 {
			if ws.ToPort != 0 {
				svcSlice = append(svcSlice, fmt.Sprintf("%d-%d %s", ws.Port, ws.ToPort, ProtocolList()[ws.Protocol]))
			} else {
				svcSlice = append(svcSlice, fmt.Sprintf("%d %s", ws.Port, ProtocolList()[ws.Protocol]))
			}
		}
		if ws.IcmpCode != 0 && ws.IcmpType != 0 {
			svcSlice = append(svcSlice, fmt.Sprintf("%d/%d %s", ws.IcmpType, ws.IcmpCode, ProtocolList()[ws.Protocol]))
		}
		if ws.ProcessName != "" {
			svcSlice = append(svcSlice, ws.ProcessName)
		}
		if ws.ServiceName != "" {
			svcSlice = append(svcSlice, ws.ServiceName)
		}
		windowsServices = append(windowsServices, strings.Join(svcSlice, " "))
	}

	// Process Service Ports
	for _, sp := range PtrToVal(s.ServicePorts) {
		var svcSlice []string
		if sp.Port != 0 && sp.Protocol != 0 {
			if sp.ToPort != 0 {
				svcSlice = append(svcSlice, fmt.Sprintf("%d-%d %s", sp.Port, sp.ToPort, ProtocolList()[sp.Protocol]))
			} else {
				svcSlice = append(svcSlice, fmt.Sprintf("%d %s", sp.Port, ProtocolList()[sp.Protocol]))
			}
		}
		if sp.IcmpCode != 0 && sp.IcmpType != 0 {
			svcSlice = append(svcSlice, fmt.Sprintf("%d/%d %s", sp.IcmpType, sp.IcmpCode, ProtocolList()[sp.Protocol]))
		} else if sp.Port == 0 && sp.Protocol != 0 {
			svcSlice = append(svcSlice, ProtocolList()[sp.Protocol])
		}
		servicePorts = append(servicePorts, strings.Join(svcSlice, " "))
	}

	return windowsServices, servicePorts
}

// ToExplorer takes a service and returns an explorer query include and exclude
func (s *Service) ToExplorer() ([]IncludeOrExclude, []IncludeOrExclude) {
	includes := []IncludeOrExclude{}
	excludes := []IncludeOrExclude{}

	// Process WindowsServices
	for _, ws := range PtrToVal(s.WindowsServices) {
		include := IncludeOrExclude{}
		exclude := IncludeOrExclude{}
		check := false
		if ws.Port != 0 {
			include.Port = ws.Port
			exclude.Port = ws.Port
			check = true
		}
		if ws.ToPort != 0 {
			include.ToPort = ws.ToPort
			exclude.ToPort = ws.ToPort
			check = true
		}
		if ws.Protocol != 0 {
			include.Proto = ws.Protocol
			exclude.Proto = ws.Protocol
			check = true
		}
		if ws.ProcessName != "" {
			include.Process = ws.ProcessName
			exclude.Process = ws.ProcessName
			check = true
		}
		if ws.ServiceName != "" {
			include.WindowsService = ws.ServiceName
			exclude.WindowsService = ws.ServiceName
			check = true
		}
		if check {
			includes = append(includes, include)
			excludes = append(excludes, exclude)
		}
	}

	// Service Ports
	for _, s := range PtrToVal(s.ServicePorts) {
		include := IncludeOrExclude{}
		exclude := IncludeOrExclude{}
		check := false
		if s.Port != 0 {
			include.Port = s.Port
			exclude.Port = s.Port
			check = true
		}
		if s.ToPort != 0 {
			include.ToPort = s.ToPort
			exclude.ToPort = s.ToPort
			check = true
		}
		if s.Protocol != 0 && s.Protocol != -1 {
			include.Proto = s.Protocol
			exclude.Proto = s.Protocol
			check = true
		}
		if check {
			includes = append(includes, include)
			excludes = append(excludes, exclude)
		}
	}

	return includes, excludes
}
