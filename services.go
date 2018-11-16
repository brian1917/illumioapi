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
	Protocol int `json:"protocol"`
	ToPort   int `json:"to_port,omitempty"`
}

// WindowsService represents port and protocol information for a Windows service
type WindowsService struct {
	IcmpCode    int    `json:"icmp_code,omitempty"`
	IcmpType    int    `json:"icmp_type,omitempty"`
	Port        int    `json:"port,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Protocol    int    `json:"protocol,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ToPort      int    `json:"to_port,omitempty"`
}

// GetAllServices returns a slice of Services for each Service in the Illumio PCE. provisionStatus must either be "draft" or "active"
func GetAllServices(pce PCE, provisionStatus string) ([]Service, APIResponse, error) {
	var services []Service
	var api APIResponse

	provisionStatus = strings.ToLower(provisionStatus)
	if provisionStatus != "active" && provisionStatus != "draft" {
		return services, api, errors.New("provisionStatus must be active or draft")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/" + provisionStatus + "/services")
	if err != nil {
		return services, api, fmt.Errorf("get all services - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return services, api, fmt.Errorf("get all services - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &services)

	// If length is 500, re-run with async
	if len(services) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return services, api, fmt.Errorf("get all services - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &services)
	}

	return services, api, nil
}

// CreateService creates a new service in the Illumio PCE
func CreateService(pce PCE, service Service) (Service, APIResponse, error) {
	var newService Service
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/sec_policy/draft/services")
	if err != nil {
		return newService, api, fmt.Errorf("create service - %s", err)
	}

	// Call the API
	serviceJSON, err := json.Marshal(service)
	if err != nil {
		return newService, api, fmt.Errorf("create service - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), pce, serviceJSON, false)
	if err != nil {
		return newService, api, fmt.Errorf("create service - %s", err)
	}

	// Unmarshal new service
	json.Unmarshal([]byte(api.RespBody), &newService)

	return newService, api, nil
}

// UpdateService updates an existing service object in the Illumio PCE
func UpdateService(pce PCE, service Service) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1" + service.Href)
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

	api, err = apicall("PUT", apiURL.String(), pce, serviceJSON, false)
	if err != nil {
		return api, fmt.Errorf("update service - %s", err)
	}

	return api, nil
}
