package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
)

// An Agent is an Agent on a Workload
type Agent struct {
	ActivePceFqdn string         `json:"active_pce_fqdn,omitempty"`
	Config        *Config        `json:"config,omitempty"`
	Href          string         `json:"href,omitempty"`
	SecureConnect *SecureConnect `json:"secure_connect,omitempty"`
	Status        *Status        `json:"status,omitempty"`
	TargetPceFqdn string         `json:"target_pce_fqdn,omitempty"`
}

// AgentHealth represents the Agent Health of the Status of a Workload
type AgentHealth struct {
	AuditEvent string `json:"audit_event,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Type       string `json:"type,omitempty"`
}

// AgentHealthErrors represents the Agent Health Errors of the Status of a Workload
// This is depreciated - use AgentHealth
type AgentHealthErrors struct {
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// Config represents the Configuration of an Agent on a Workload
type Config struct {
	LogTraffic               bool   `json:"log_traffic,omitempty"`
	Mode                     string `json:"mode,omitempty"`
	SecurityPolicyUpdateMode string `json:"security_policy_update_mode,omitempty"`
}

// DeletedBy represents the Deleted By property of an object
type DeletedBy struct {
	Href string `json:"href,omitempty"`
}

// An Interface represent the Interfaces of a Workload
type Interface struct {
	Address               string `json:"address,omitempty"`
	CidrBlock             int    `json:"cidr_block,omitempty"`
	DefaultGatewayAddress string `json:"default_gateway_address,omitempty"`
	FriendlyName          string `json:"friendly_name,omitempty"`
	LinkState             string `json:"link_state,omitempty"`
	Name                  string `json:"name,omitempty"`
}

// OpenServicePorts represents open ports for a service running on a workload
type OpenServicePorts struct {
	Address        string `json:"address,omitempty"`
	Package        string `json:"package,omitempty"`
	Port           int    `json:"port,omitempty"`
	ProcessName    string `json:"process_name,omitempty"`
	Protocol       int    `json:"protocol,omitempty"`
	User           string `json:"user,omitempty"`
	WinServiceName string `json:"win_service_name,omitempty"`
}

// A Workload is a Workload object in the PCE
type Workload struct {
	Agent                 *Agent       `json:"agent,omitempty"`
	CreatedAt             string       `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy   `json:"created_by,omitempty"`
	DataCenter            string       `json:"data_center,omitempty"`
	DataCenterZone        string       `json:"data_center_zone,omitempty"`
	DeleteType            string       `json:"delete_type,omitempty"`
	Deleted               *bool        `json:"deleted,omitempty"`
	DeletedAt             string       `json:"deleted_at,omitempty"`
	DeletedBy             *DeletedBy   `json:"deleted_by,omitempty"`
	Description           string       `json:"description,omitempty"`
	ExternalDataReference string       `json:"external_data_reference,omitempty"`
	ExternalDataSet       string       `json:"external_data_set,omitempty"`
	Hostname              string       `json:"hostname,omitempty"`
	Href                  string       `json:"href,omitempty"`
	Interfaces            []*Interface `json:"interfaces,omitempty"`
	Labels                []*Label     `json:"labels,omitempty"`
	Name                  string       `json:"name,omitempty"`
	Online                bool         `json:"online,omitempty"`
	OsDetail              string       `json:"os_detail,omitempty"`
	OsID                  string       `json:"os_id,omitempty"`
	PublicIP              string       `json:"public_ip,omitempty"`
	ServicePrincipalName  string       `json:"service_principal_name,omitempty"`
	ServiceProvider       string       `json:"service_provider,omitempty"`
	Services              *Services    `json:"services,omitempty"`
	UpdatedAt             string       `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy   `json:"updated_by,omitempty"`
}

// SecureConnect represents SecureConnect for an Agent on a Workload
type SecureConnect struct {
	MatchingIssuerName string `json:"matching_issuer_name,omitempty"`
}

// Services represent the Services running on a Workload
type Services struct {
	CreatedAt        string              `json:"created_at,omitempty"`
	OpenServicePorts []*OpenServicePorts `json:"open_service_ports,omitempty"`
	UptimeSeconds    int                 `json:"uptime_seconds,omitempty"`
}

// Status represents the Status of an Agent on a Workload
type Status struct {
	AgentHealth              []*AgentHealth     `json:"agent_health,omitempty"`
	AgentHealthErrors        *AgentHealthErrors `json:"agent_health_errors,omitempty"`
	AgentVersion             string             `json:"agent_version,omitempty"`
	FirewallRuleCount        int                `json:"firewall_rule_count,omitempty"`
	FwConfigCurrent          bool               `json:"fw_config_current,omitempty"`
	LastHeartbeatOn          string             `json:"last_heartbeat_on,omitempty"`
	ManagedSince             string             `json:"managed_since,omitempty"`
	SecurityPolicyAppliedAt  string             `json:"security_policy_applied_at,omitempty"`
	SecurityPolicyReceivedAt string             `json:"security_policy_received_at,omitempty"`
	SecurityPolicyRefreshAt  string             `json:"security_policy_refresh_at,omitempty"`
	SecurityPolicySyncState  string             `json:"security_policy_sync_state,omitempty"`
	UID                      string             `json:"uid,omitempty"`
	UptimeSeconds            int                `json:"uptime_seconds,omitempty"`
}

// GetAllWorkloads returns an slice of workloads for each workload in the Illumio PCE
func GetAllWorkloads(pce PCE) ([]Workload, APIResponse, error) {
	var workloads []Workload
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/workloads")
	if err != nil {
		return nil, api, fmt.Errorf("get all workloads - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all workloads - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &workloads)

	// If length is 500, re-run with async
	if len(workloads) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all workloads - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &workloads)
	}

	return workloads, api, nil
}

// CreateWorkload creates a new workload in the Illumio PCE
func CreateWorkload(pce PCE, workload Workload) (Workload, APIResponse, error) {
	var newWL Workload
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/workloads")
	if err != nil {
		return newWL, api, fmt.Errorf("create workload - %s", err)
	}

	// Call the API
	workloadJSON, err := json.Marshal(workload)
	if err != nil {
		return newWL, api, fmt.Errorf("create workload - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), pce, workloadJSON, false)
	if err != nil {
		return newWL, api, fmt.Errorf("create workload - %s", err)
	}

	// Marshal JSON
	json.Unmarshal([]byte(api.RespBody), &newWL)

	return newWL, api, nil
}

// UpdateWorkload updates an existing workload in the Illumio PCE
func UpdateWorkload(pce PCE, workload Workload) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1" + workload.Href)
	if err != nil {
		return api, fmt.Errorf("update workload - %s", err)
	}

	// Remove fields that shouldn't be available for updating
	workload.CreatedAt = ""
	workload.CreatedBy = nil
	workload.DeleteType = ""
	workload.Deleted = nil
	workload.DeletedAt = ""
	workload.DeletedBy = nil
	workload.Href = ""
	workload.UpdatedAt = ""
	workload.UpdatedBy = nil
	workload.Services = nil

	// Call the API
	workloadJSON, err := json.Marshal(workload)
	if err != nil {
		return api, fmt.Errorf("update workload - %s", err)
	}

	api, err = apicall("PUT", apiURL.String(), pce, workloadJSON, false)
	if err != nil {
		return api, fmt.Errorf("update workload - %s", err)
	}

	return api, nil
}

// BulkWorkload on Workload updates an existing workload in the Illumio PCE
//
// Method must be create, update, or delete
func BulkWorkload(pce PCE, workloads []Workload, method string) ([]APIResponse, error) {
	var apiResps []APIResponse
	var err error

	// Check on method
	method = strings.ToLower(method)
	if method != "create" && method != "update" && method != "delete" {
		return apiResps, errors.New("bulk workload error - method must be create, update, or delete")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/workloads/bulk_" + method)
	if err != nil {
		return apiResps, fmt.Errorf("bulk workload error - %s", err)
	}

	// If the method is delete, we can only send Hrefs
	if method == "delete" {
		hrefWorkloads := []Workload{}
		for _, workload := range workloads {
			hrefWorkloads = append(hrefWorkloads, Workload{Href: workload.Href})
		}
		// Re-assign workloads to just the HREF
		workloads = hrefWorkloads
	}

	// Figure out how many API calls we need to make
	numAPICalls := int(math.Ceil(float64(len(workloads)) / 1000))

	// Build the array to be passed to the API
	apiArrays := [][]Workload{}
	for i := 0; i < numAPICalls; i++ {
		// Get 1,000 elements if this is not the last array
		if (i + 1) != numAPICalls {
			apiArrays = append(apiArrays, workloads[i*1000:(1+i)*1000])
			// Get the rest on the last array
		} else {
			apiArrays = append(apiArrays, workloads[i*1000:])
		}
	}

	// Call the API for each array
	for _, apiArray := range apiArrays {
		workloadsJSON, err := json.Marshal(apiArray)
		if err != nil {
			return apiResps, fmt.Errorf("bulk workload error - %s", err)
		}
		api, err := apicall("PUT", apiURL.String(), pce, workloadsJSON, false)
		if err != nil {
			return apiResps, fmt.Errorf("bulk workload error - %s", err)
		}

		apiResps = append(apiResps, api)
	}

	return apiResps, nil
}
