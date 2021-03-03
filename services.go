package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Service represent a service in the Illumio PCE
type Service struct {
	CreatedAt             string            `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy        `json:"created_by,omitempty"`
	DeletedAt             string            `json:"deleted_at,omitempty"`
	DeletedBy             *DeletedBy        `json:"deleted_by,omitempty"`
	Description           string            `json:"description,omitempty"`
	DescriptionURL        string            `json:"description_url,omitempty"`
	ExternalDataReference string            `json:"external_data_reference,omitempty"`
	ExternalDataSet       string            `json:"external_data_set,omitempty"`
	Href                  string            `json:"href,omitempty"`
	Name                  string            `json:"name"`
	ProcessName           string            `json:"process_name,omitempty"`
	ServicePorts          []*ServicePort    `json:"service_ports,omitempty"`
	UpdateType            string            `json:"update_type,omitempty"`
	UpdatedAt             string            `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy        `json:"updated_by,omitempty"`
	WindowsServices       []*WindowsService `json:"windows_services,omitempty"`
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

// WindowsService represents port and protocol information for a Windows service
type WindowsService struct {
	IcmpCode    int    `json:"icmp_code,omitempty"`
	IcmpType    int    `json:"icmp_type,omitempty"`
	Port        int    `json:"port,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Protocol    int    `json:"proto,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ToPort      int    `json:"to_port,omitempty"`
}

// GetAllServices returns a slice of Services for each Service in the Illumio PCE.
// provisionStatus must either be "draft" or "active".
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
func (p *PCE) GetAllServices(provisionStatus string) ([]Service, APIResponse, error) {
	var api APIResponse

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return nil, api, errors.New("provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/" + provisionStatus + "/services")
	if err != nil {
		return nil, api, fmt.Errorf("get all services - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all services - %s", err)
	}

	var services []Service
	json.Unmarshal([]byte(api.RespBody), &services)

	// If length is 500, re-run with async
	if len(services) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all services - %s", err)
		}

		// Unmarshal response to struct
		var asyncServices []Service
		json.Unmarshal([]byte(api.RespBody), &asyncServices)

		return asyncServices, api, nil
	}

	// Return if there is less than 500
	return services, api, nil
}

// CreateService creates a new service in the Illumio PCE
func (p *PCE) CreateService(service Service) (Service, APIResponse, error) {
	var newService Service
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/sec_policy/draft/services")
	if err != nil {
		return newService, api, fmt.Errorf("create service - %s", err)
	}

	// Call the API
	serviceJSON, err := json.Marshal(service)
	if err != nil {
		return newService, api, fmt.Errorf("create service - %s", err)
	}

	api.ReqBody = string(serviceJSON)

	api, err = apicall("POST", apiURL.String(), *p, serviceJSON, false)
	if err != nil {
		return newService, api, fmt.Errorf("create service - %s", err)
	}

	// Unmarshal new service
	json.Unmarshal([]byte(api.RespBody), &newService)

	return newService, api, nil
}

// UpdateService updates an existing service object in the Illumio PCE
func (p *PCE) UpdateService(service Service) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + service.Href)
	if err != nil {
		return api, fmt.Errorf("update service - %s", err)
	}

	// Remove fields that shouldn't be available for updating
	service.CreatedAt = ""
	service.CreatedBy = nil
	service.Href = ""
	service.UpdateType = ""
	service.UpdatedAt = ""
	service.UpdatedBy = nil

	// Call the API
	serviceJSON, err := json.Marshal(service)
	if err != nil {
		return api, fmt.Errorf("update service - %s", err)
	}

	api.ReqBody = string(serviceJSON)

	api, err = apicall("PUT", apiURL.String(), *p, serviceJSON, false)
	if err != nil {
		return api, fmt.Errorf("update service - %s", err)
	}

	return api, nil
}

// ParseService returns a slice of WindowsServices and ServicePorts from an Illumio service object
func (s *Service) ParseService() (windowsServices, servicePorts []string) {

	// Create a string for Windows Services
	for _, ws := range s.WindowsServices {
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
	for _, sp := range s.ServicePorts {
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
