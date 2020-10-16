package illumioapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	CidrBlock             *int   `json:"cidr_block,omitempty"`
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
	IgnoredInterfaceNames []string     `json:"ignored_interface_names,omitempty"`
	Interfaces            []*Interface `json:"interfaces,omitempty"`
	Labels                []*Label     `json:"labels,omitempty"` // This breaks the removing all labels
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
	InstanceID               string             `json:"instance_id,omitempty"`
	LastHeartbeatOn          string             `json:"last_heartbeat_on,omitempty"`
	ManagedSince             string             `json:"managed_since,omitempty"`
	SecurityPolicyAppliedAt  string             `json:"security_policy_applied_at,omitempty"`
	SecurityPolicyReceivedAt string             `json:"security_policy_received_at,omitempty"`
	SecurityPolicyRefreshAt  string             `json:"security_policy_refresh_at,omitempty"`
	SecurityPolicySyncState  string             `json:"security_policy_sync_state,omitempty"`
	Status                   string             `json:"status,omitempty"`
	UID                      string             `json:"uid,omitempty"`
	UptimeSeconds            int                `json:"uptime_seconds,omitempty"`
}

// Unpair is the payload for using the API to unpair workloads.
type Unpair struct {
	Workloads      []Workload `json:"workloads"`
	IPTableRestore string     `json:"ip_table_restore"`
}

// GetAllWorkloads returns an slice of workloads in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
func (p *PCE) GetAllWorkloads() ([]Workload, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/workloads")
	if err != nil {
		return nil, api, fmt.Errorf("get all workloads - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all workloads - %s", err)
	}

	var workloads []Workload
	json.Unmarshal([]byte(api.RespBody), &workloads)

	// If length is 500, re-run with async
	if len(workloads) >= 500 {
		// Call async
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all workloads - %s", err)
		}
		// Unmarshal response to asyncWklds and return
		var asyncWklds []Workload
		json.Unmarshal([]byte(api.RespBody), &asyncWklds)

		return asyncWklds, api, nil
	}

	// Return if less than 500
	return workloads, api, nil
}

// GetWkldByHref returns the workload with a specific href
func (p *PCE) GetWkldByHref(href string) (Workload, APIResponse, error) {
	// Build the API URL
	apiURL, err := url.Parse(fmt.Sprintf("https://%s:%d/api/v2%s", pceSanitization(p.FQDN), p.Port, href))
	if err != nil {
		return Workload{}, APIResponse{}, fmt.Errorf("get workload by href - %s", err)
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return Workload{}, api, fmt.Errorf("get workload by href - %s", err)
	}

	var wkld Workload
	json.Unmarshal([]byte(api.RespBody), &wkld)

	return wkld, api, nil
}

// GetWkldHrefMap returns a map of all workloads with the Href as the key.
func (p *PCE) GetWkldHrefMap() (map[string]Workload, APIResponse, error) {

	m := make(map[string]Workload)
	wklds, a, err := p.GetAllWorkloads()
	if err != nil {
		return nil, a, err
	}
	for _, w := range wklds {
		m[w.Href] = w
	}
	return m, a, nil

}

// GetWkldHostMap returns a map of all workloads with the hostname as the key.
func (p *PCE) GetWkldHostMap() (map[string]Workload, APIResponse, error) {

	m := make(map[string]Workload)
	wklds, a, err := p.GetAllWorkloads()
	if err != nil {
		return nil, a, err
	}
	for _, w := range wklds {
		m[w.Hostname] = w
	}
	return m, a, nil

}

// CreateWorkload creates a new unmanaged workload in the Illumio PCE
func (p *PCE) CreateWorkload(workload Workload) (Workload, APIResponse, error) {
	var newWL Workload
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/workloads")
	if err != nil {
		return newWL, api, fmt.Errorf("create workload - %s", err)
	}

	// Call the API
	workloadJSON, err := json.Marshal(workload)
	if err != nil {
		return newWL, api, fmt.Errorf("create workload - %s", err)
	}
	api, err = apicall("POST", apiURL.String(), *p, workloadJSON, false)
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
func (p *PCE) UpdateWorkload(workload Workload) (APIResponse, error) {
	var api APIResponse
	var err error

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + workload.Href)
	if err != nil {
		return api, fmt.Errorf("update workload - %s", err)
	}

	workload.SanitizePut()

	// Call the API
	workloadJSON, err := json.Marshal(workload)
	if err != nil {
		return api, fmt.Errorf("update workload - %s", err)
	}

	api, err = apicall("PUT", apiURL.String(), *p, workloadJSON, false)
	if err != nil {
		return api, fmt.Errorf("update workload - %s", err)
	}

	return api, nil
}

// ChangeLabel updates a workload struct with new label href.
// It does not call the Illumio API to update the workload in the PCE. Use pce.UpdateWorkload() or bulk update for that.
// The method returns the labelMapH in case it needs to create a new label.
func (w *Workload) ChangeLabel(pce PCE, targetKey, newValue string) (PCE, error) {
	var updatedLabels []*Label
	var newLabel Label
	var err error
	var ok bool

	// Iterate through each of the workloads labels
	for _, l := range w.Labels {
		// If they key isn't the target key, we add it to the updated labels
		if pce.LabelMapH[l.Href].Key != targetKey {
			updatedLabels = append(updatedLabels, &Label{Href: l.Href})
		}
	}

	// If our new label isn't blank, we need to get it's href and attach to array
	if newValue == "" {
		w.Labels = updatedLabels
		return pce, nil
	}

	// If our new label is not blank, we need to get it's href and add it to the array
	if newLabel, ok = pce.LabelMapKV[targetKey+newValue]; !ok {
		// If it doesn't exist, we create it and put it back into the label maps
		newLabel, _, err = pce.CreateLabel(Label{Key: targetKey, Value: newValue})
		if err != nil {
			return pce, err
		}
		pce.LabelMapH[newLabel.Href] = newLabel
		pce.LabelMapKV[newLabel.Key+newLabel.Value] = newLabel
	}
	// Append the new label to our label slice
	updatedLabels = append(updatedLabels, &Label{Href: newLabel.Href})

	w.Labels = updatedLabels
	return pce, nil
}

// BulkWorkload takes a bulk action on an array of workloads.
// Method must be create, update, or delete
func (p *PCE) BulkWorkload(workloads []Workload, method string) ([]APIResponse, error) {
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
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/workloads/bulk_" + method)
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

		api, err := apicall("PUT", apiURL.String(), *p, workloadsJSON, false)

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
	w.Services = nil

	// Managed workloads
	if w.Agent != nil && w.Agent.Status != nil {
		w.Hostname = ""
		w.Interfaces = nil
		w.Online = false
		w.OsDetail = ""
		w.OsID = ""
		w.PublicIP = ""
		w.Services = nil
		w.Online = false
		w.Agent.Status = nil
		w.Agent.SecureConnect = nil
		w.Agent.ActivePceFqdn = "" // For supercluster-paired workloads
		w.Agent.TargetPceFqdn = "" // For supercluster-paired workloads
		w.Agent.Config.SecurityPolicyUpdateMode = ""
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

// GetRole takes a map of labels with the href string as the key and returns the role label for a workload.
// To get the LabelMap call GetLabelMapH.
func (w *Workload) GetRole(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "role" {
			return labelMap[l.Href]
		}
	}
	return Label{}
}

// GetApp takes a map of labels with the href string as the key and returns the app label for a workload.
// To get the LabelMap call GetLabelMapH.
func (w *Workload) GetApp(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "app" {
			return labelMap[l.Href]
		}
	}
	return Label{}
}

// GetEnv takes a map of labels with the href string as the key and returns the env label for a workload.
// To get the LabelMap call GetLabelMapH.
func (w *Workload) GetEnv(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "env" {
			return labelMap[l.Href]
		}
	}
	return Label{}
}

// GetLoc takes a map of labels with the href string as the key and returns the loc label for a workload.
// To get the LabelMap call GetLabelMapH.
func (w *Workload) GetLoc(labelMap map[string]Label) Label {
	for _, l := range w.Labels {
		if labelMap[l.Href].Key == "loc" {
			return labelMap[l.Href]
		}
	}
	return Label{}
}

// LabelsMatch checks if the workload matches the provided labels.
// Blank values ("") for role, app, env, or loc mean no label assigned for that key.
// A single asterisk (*) can be used to represent any in a particular key.
// For example, using "*" for role will return true as long as the app, env, and loc match.
func (w *Workload) LabelsMatch(role, app, env, loc string, labelMap map[string]Label) bool {
	if (role == "*" || w.GetRole(labelMap).Value == role) &&
		(app == "*" || w.GetApp(labelMap).Value == app) &&
		(env == "*" || w.GetEnv(labelMap).Value == env) &&
		(loc == "*" || w.GetLoc(labelMap).Value == loc) {
		return true
	}
	return false
}

// GetAppGroup returns the app group string of a workload in the format of App | Env.
// If the workload does not have an app or env label, "NO APP GROUP" is returned.
// Use GetAppGroupL to include the loc label in the app group.
func (w *Workload) GetAppGroup(labelMap map[string]Label) string {
	if w.GetApp(labelMap).Href == "" || w.GetEnv(labelMap).Href == "" {
		return "NO APP GROUP"
	}

	return fmt.Sprintf("%s | %s", w.GetApp(labelMap).Value, w.GetEnv(labelMap).Value)
}

// GetAppGroupL returns the app group string of a workload in the format of App | Env | Loc.
// If the workload does not have an app, env, or loc label, "NO APP GROUP" is returned.
// Use GetAppGroup to only use app and env in App Group.
func (w *Workload) GetAppGroupL(labelMap map[string]Label) string {
	if w.GetApp(labelMap).Href == "" || w.GetEnv(labelMap).Href == "" || w.GetLoc(labelMap).Href == "" {
		return "NO APP GROUP"
	}

	return fmt.Sprintf("%s | %s | %s", w.GetApp(labelMap).Value, w.GetEnv(labelMap).Value, w.GetLoc(labelMap).Value)
}

// GetMode returns the mode of the workloads.
// Modes are unmanaged, idle, build, test, enforced-no, enforced-low, enforced-high.
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
// To reflect the change in the PCE uset SetMode method followed by PCE.UpdateWorkload() method
//
// Valid options: idle, build, test, enforced-no, enforced-low, and enforced-high.
// The enforced options represent no logging, low details, and high detail.
func (w *Workload) SetMode(m string) error {

	m = strings.ToLower(m)

	switch m {

	case "idle":
		w.Agent.Config.Mode = "idle"

	case "build":
		w.Agent.Config.Mode = "illuminated"
		w.Agent.Config.LogTraffic = false

	case "test":
		w.Agent.Config.Mode = "illuminated"
		w.Agent.Config.LogTraffic = true

	case "enforced-no":
		w.Agent.Config.Mode = "enforced"
		w.Agent.Config.VisibilityLevel = "flow_off"
		w.Agent.Config.LogTraffic = false

	case "enforced-low":
		w.Agent.Config.Mode = "enforced"
		w.Agent.Config.VisibilityLevel = "flow_drops"
		w.Agent.Config.LogTraffic = true

	case "enforced-high":
		w.Agent.Config.Mode = "enforced"
		w.Agent.Config.VisibilityLevel = "flow_summary"
		w.Agent.Config.LogTraffic = true

	default:
		return fmt.Errorf("%s is not a valid mode. See SetMode documentation for valid modes", m)

	}
	return nil
}

//GetID returns the ID from the Href of an Agent
func (a *Agent) GetID() string {
	x := strings.Split(a.Href, "/")
	return x[len(x)-1]
}

// WorkloadUpgrade upgrades the VEN version on the workload
func (p *PCE) WorkloadUpgrade(wkldHref, targetVersion string) (APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + wkldHref + "/upgrade")
	if err != nil {
		return APIResponse{}, fmt.Errorf("upgrade workload - %s", err)
	}

	// Call the API
	api, err := apicall("POST", apiURL.String(), *p, json.RawMessage(fmt.Sprintf("{\"release\": \"%s\"}", targetVersion)), false)
	if err != nil {
		return api, fmt.Errorf("upgrade workload - %s", err)
	}

	return api, nil

}

// WorkloadsUnpair unpairs workloads. There is no limit to the length of []Workloads. The method
// chunks the API calls into groups of 1,000 to conform to the Illumio API.
func (p *PCE) WorkloadsUnpair(wklds []Workload, ipTablesRestore string) ([]APIResponse, error) {

	// Build the payload
	var targetWklds []Workload
	for _, w := range wklds {
		targetWklds = append(targetWklds, Workload{Href: w.Href})
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/workloads/unpair")
	if err != nil {
		return nil, fmt.Errorf("unpair error - %s", err)
	}

	// Figure out how many API calls we need to make
	numAPICalls := int(math.Ceil(float64(len(targetWklds)) / 1000))

	// Build the array to be passed to the API
	apiArrays := [][]Workload{}
	for i := 0; i < numAPICalls; i++ {
		// Get 1,000 elements if this is not the last array
		if (i + 1) != numAPICalls {
			apiArrays = append(apiArrays, targetWklds[i*1000:(1+i)*1000])
			// Get the rest on the last array
		} else {
			apiArrays = append(apiArrays, targetWklds[i*1000:])
		}
	}

	// Call the API for each array
	var apiResps []APIResponse
	for _, apiArray := range apiArrays {
		// Marshal the payload
		unpair := Unpair{IPTableRestore: ipTablesRestore, Workloads: apiArray}
		payload, err := json.Marshal(unpair)
		if err != nil {
			return nil, fmt.Errorf("unpair error - %s", err)
		}
		// Make the API call and append the response to the results
		api, err := apicall("PUT", apiURL.String(), *p, payload, false)
		apiResps = append(apiResps, api)
		if err != nil {
			return apiResps, fmt.Errorf("unpair error - %s", err)
		}
	}
	return apiResps, nil
}

// GetDefaultGW returns the default gateway for a workload.
// If the workload does not have a default gateway (many unmanaged workloads) it will return "NA"
func (w *Workload) GetDefaultGW() string {
	for _, i := range w.Interfaces {
		if i.DefaultGatewayAddress != "" {
			return i.DefaultGatewayAddress
		}
	}
	return "NA"
}

// GetIPWithDefaultGW returns the IP address of the interface that has the default gateway
// If the workload does not have a default gateway (many unmanaged workloads), it will return "NA"
func (w *Workload) GetIPWithDefaultGW() string {
	for _, i := range w.Interfaces {
		if i.DefaultGatewayAddress != "" {
			return i.Address
		}
	}
	return "NA"
}

// GetNetMaskWithDefaultGW returns the netmask of the ip address that has the default gateway
// If the workload does not have a default gateway (many unmanaged workloads), it will return "NA"
func (w *Workload) GetNetMaskWithDefaultGW() string {
	for _, i := range w.Interfaces {
		if i.DefaultGatewayAddress != "" {
			return w.GetNetMask(i.Address)
		}
	}
	return "NA"
}

// GetNetworkWithDefaultGateway returns the CIDR notation of the network of the interface with the default gateway.
// If the workload does not have a default gateway (many unmanaged workloads), it will return "NA"
func (w *Workload) GetNetworkWithDefaultGateway() string {
	for _, i := range w.Interfaces {
		if i.DefaultGatewayAddress != "" && i.CidrBlock != nil {
			_, net, err := net.ParseCIDR(fmt.Sprintf("%s/%d", i.Address, *i.CidrBlock))
			if err != nil {
				return "NA"
			}
			return net.String()
		}
	}
	return "NA"
}

// GetCIDR returns the CIDR Block for a workload's IP address
// The CIDR value is returned as a string (e.g., "/24").
// If the CIDR value is not known (e.g., unmanaged workloads) it returns "NA"
// If the provided IP address is not attached to the workload, GetCIDR returns "NA".
func (w *Workload) GetCIDR(ip string) string {
	for _, i := range w.Interfaces {
		if i.Address == ip {
			if i.CidrBlock != nil {
				return fmt.Sprintf("/%d", *i.CidrBlock)
			}
			return "NA"
		}
	}
	return "NA"
}

// GetInterfaceName returns the interface name for a workload's IP address
// If the provided IP address is not attached to the workload, GetInterfaceName returns "NA".
func (w *Workload) GetInterfaceName(ip string) string {
	for _, i := range w.Interfaces {
		if i.Address == ip {
			return i.Name
		}
	}
	return "NA"
}

// GetNetMask returns the netmask for a workload's IP address
// The value is returned as a string (e.g., "255.0.0.0")
// If the value is not known (e.g., unmanaged workloads) it returns "NA"
// If the provided IP address is not attached to the workload, GetNetMask returns "NA".
func (w *Workload) GetNetMask(ip string) string {
	for _, i := range w.Interfaces {
		if i.Address == ip {
			if i.CidrBlock != nil {
				_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", i.Address, *i.CidrBlock))
				// IPv4
				if len(ipNet.Mask) == 4 {
					return fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])
				}
				if len(ipNet.Mask) > 4 {
					return ipNet.Mask.String()
				}
			}
			return "NA"
		}
	}
	return "NA"
}

// GetNetwork returns the network of a workload's IP address.
func (w *Workload) GetNetwork(ip string) string {
	for _, i := range w.Interfaces {
		if i.Address == ip {
			if i.CidrBlock != nil {
				_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("%s/%d", i.Address, *i.CidrBlock))
				// IPv4
				if len(ipNet.Mask) == 4 {
					return fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])
				}
				if len(ipNet.Mask) > 4 {
					return ipNet.Mask.String()
				}
			}
			return "NA"
		}
	}
	return "NA"
}

// HoursSinceLastHeartBeat returns the hours since the last beat.
// -9999 is returned for unmanaged workloads or when it cannot be calculated.
func (w *Workload) HoursSinceLastHeartBeat() float64 {
	if w.GetMode() == "unmanaged" {
		return -9999
	}
	t, err := time.Parse(time.RFC3339, w.Agent.Status.LastHeartbeatOn)
	if err != nil {
		return -9999
	}
	return time.Now().UTC().Sub(t).Hours()
}
