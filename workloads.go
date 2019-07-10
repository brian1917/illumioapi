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
	LogTraffic               bool   `json:"log_traffic"`
	Mode                     string `json:"mode,omitempty"`
	SecurityPolicyUpdateMode string `json:"security_policy_update_mode,omitempty"`
	VisibilityLevel          string `json:"visibility_level,omitempty"`
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

// A Workload represents a workload in the PCE
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
	Services              []*Services  `json:"services,omitempty"`
	UpdatedAt             string       `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy   `json:"updated_by,omitempty"`
	// App                   Label        `json:"-"`
	// Role                  Label        `json:"-"`
	// Env                   Label        `json:"-"`
	// Loc                   Label        `json:"-"`
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

// GetAllWorkloads returns an slice of workloads in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
func GetAllWorkloads(pce PCE) ([]Workload, APIResponse, error) {
	var workloads []Workload
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/workloads")
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

// CreateWorkload creates a new unmanaged workload in the Illumio PCE
func CreateWorkload(pce PCE, workload Workload) (Workload, APIResponse, error) {
	var newWL Workload
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/workloads")
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
// The provided workload struct must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func UpdateWorkload(pce PCE, workload Workload) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2" + workload.Href)
	if err != nil {
		return api, fmt.Errorf("update workload - %s", err)
	}

	workload.SanitizePut()

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

// ChangeLabel updates a workload struct with new label href.
// It does not call the Illumio API. To reflect the change in your PCE,
// you'd use UpdateLabel method on the workload struct and then use the UpdateWorkload function
func (w *Workload) ChangeLabel(pce PCE, key, value string) error {
	var updatedLabels []*Label
	for _, l := range w.Labels {
		x, _, err := GetLabelbyHref(pce, l.Href)
		if err != nil {
			return fmt.Errorf("error updating workload - %s", err)
		}
		if x.Key == key {
			// Get our new label's href
			newLabel, _, err := GetLabelbyKeyValue(pce, key, value)
			if err != nil {
				return fmt.Errorf("error updating workload - %s", err)
			}
			// Create the label if it doesn't exist
			if newLabel.Href == "" {
				createdLabel, _, err := CreateLabel(pce, Label{Key: key, Value: value})
				if err != nil {
					return fmt.Errorf("error updating workload - %s", err)
				}
				updatedLabels = append(updatedLabels, &Label{Href: createdLabel.Href})
				// If the new label does exist, add it to the slice
			} else {
				updatedLabels = append(updatedLabels, &Label{Href: newLabel.Href})
			}
		} else {
			updatedLabels = append(updatedLabels, &Label{Href: l.Href})
		}
		w.Labels = updatedLabels
	}
	return nil
}

// BulkWorkload takes a bulk action on an array of workloads.
// Method must be create, update, or delete
func BulkWorkload(pce PCE, workloads []Workload, method string) ([]APIResponse, error) {
	var apiResps []APIResponse
	var err error

	// Check on method
	method = strings.ToLower(method)
	if method != "create" && method != "update" && method != "delete" {
		return apiResps, errors.New("bulk workload error - method must be create, update, or delete")
	}

	// Sanitize update
	if method == "update" {
		sanitizedWLs := []Workload{}
		for _, workload := range workloads {
			workload.SanitizeBulkUpdate()
			sanitizedWLs = append(sanitizedWLs, workload)
		}
		workloads = sanitizedWLs
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/workloads/bulk_" + method)
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

		// Uncomment this line if you want to print the JSON object
		// fmt.Println(string(workloadsJSON))

		api, err := apicall("PUT", apiURL.String(), pce, workloadsJSON, false)

		apiResps = append(apiResps, api)

		if err != nil {
			return apiResps, fmt.Errorf("bulk workload error - %s", err)
		}

	}

	return apiResps, nil
}

// SanitizeBulkUpdate removes the properites necessary for a bulk update
func (w *Workload) SanitizeBulkUpdate() {

	// All Workloads
	w.CreatedAt = ""
	w.CreatedBy = nil
	w.DeleteType = ""
	w.Deleted = nil
	w.DeletedAt = ""
	w.DeletedBy = nil
	w.UpdatedAt = ""
	w.UpdatedBy = nil

	// Managed workloads
	if w.Agent != nil && w.Agent.Status != nil {
		w.Hostname = ""
		w.Interfaces = nil
		w.Online = false
		w.OsDetail = ""
		w.OsID = ""
		w.PublicIP = ""
		w.Agent.Status = nil
		w.Services = nil
		w.Online = false
	}

	// Replace Labels with Hrefs
	newLabels := []*Label{}
	for _, l := range w.Labels {
		newLabel := Label{Href: l.Href}
		newLabels = append(newLabels, &newLabel)
	}
	w.Labels = newLabels
}

// SanitizePut removes the necessary properties to update an unmanaged and managed workload
func (w *Workload) SanitizePut() {
	w.SanitizeBulkUpdate()
	w.Href = ""
}

// GetRole returns the role label for a workload
func (w *Workload) GetRole(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "role" {
			return *l
		}
	}
	return Label{}
}

// GetApp returns the application label for a workload
func (w *Workload) GetApp(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "app" {
			return *l
		}
	}
	return Label{}
}

// GetEnv returns the environment label for a workload
func (w *Workload) GetEnv(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "env" {
			return *l
		}
	}
	return Label{}
}

// GetLoc returns the location label for a workload
func (w *Workload) GetLoc(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "loc" {
			return *l
		}
	}
	return Label{}
}

// GetMode returns the mode - unmanaged, idle, build, test, enforce - of the workload
func (w *Workload) GetMode() string {
	if w.Agent == nil || w.Agent.Href == "" {
		return "unmanaged"
	}
	if w.Agent.Config.Mode == "illuminated" && !w.Agent.Config.LogTraffic {
		return "build"
	}
	if w.Agent.Config.Mode == "illuminated" && w.Agent.Config.LogTraffic {
		return "test"
	}
	if w.Agent.Config.Mode == "enforced" && w.Agent.Config.VisibilityLevel == "flow_summary" {
		return "enforced-high"
	}
	if w.Agent.Config.Mode == "enforced" && w.Agent.Config.VisibilityLevel == "flow_drops" {
		return "enforced-low"
	}
	if w.Agent.Config.Mode == "enforced" && w.Agent.Config.VisibilityLevel == "flow_off" {
		return "enforced-no"
	}
	return "idle"
}

// SetMode adjusts the workload struct to reflect the assigned mode.
// Nothing is changed in the PCE.
// To reflect the change in the PCE uset SetMode method followed by UpdateWorkload function
//
// 0 - idle
//
// 1 - build
//
// 2 - test
//
// 3 - enforced with no detail
//
// 4 - enforced with low detail
//
// 5 - enforced with high detail
func (w *Workload) SetMode(m int) {
	switch m {
	// idle
	case 0:
		w.Agent.Config.Mode = "idle"
	// build
	case 1:
		w.Agent.Config.Mode = "illuminated"
		w.Agent.Config.LogTraffic = false
	// test
	case 2:
		w.Agent.Config.Mode = "illuminated"
		w.Agent.Config.LogTraffic = true
	//enforced with no detail
	case 3:
		w.Agent.Config.Mode = "enforced"
		w.Agent.Config.VisibilityLevel = "flow_off"
		w.Agent.Config.LogTraffic = false
	// enforced with low detail
	case 4:
		w.Agent.Config.Mode = "enforced"
		w.Agent.Config.VisibilityLevel = "flow_drops"
		w.Agent.Config.LogTraffic = true
	// enforced with high detail
	case 5:
		w.Agent.Config.Mode = "enforced"
		w.Agent.Config.VisibilityLevel = "flow_summary"
		w.Agent.Config.LogTraffic = true

	}
}
