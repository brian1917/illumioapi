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

// A Workload represents a workload in the PCE
type Workload struct {
	Href                  string                `json:"href,omitempty"`
	Description           *string               `json:"description,omitempty"`
	Name                  *string               `json:"name,omitempty"`
	Hostname              *string               `json:"hostname,omitempty"`
	Labels                *[]Label              `json:"labels,omitempty"`
	Interfaces            *[]Interface          `json:"interfaces,omitempty"`
	IgnoredInterfaceNames *[]string             `json:"ignored_interface_names,omitempty"`
	PublicIP              *string               `json:"public_ip,omitempty"`
	Online                *bool                 `json:"online,omitempty"`
	EnforcementMode       *string               `json:"enforcement_mode,omitempty"`
	VisibilityLevel       *string               `json:"visibility_level,omitempty"`
	OsDetail              *string               `json:"os_detail,omitempty"`
	OsID                  *string               `json:"os_id,omitempty"`
	Services              *WkldServices         `json:"services,omitempty"`
	DistinguishedName     *string               `json:"distinguished_name,omitempty"`
	ServicePrincipalName  *string               `json:"service_principal_name,omitempty"`
	VEN                   *VEN                  `json:"ven,omitempty"`
	Agent                 *Agent                `json:"agent,omitempty"`
	ServiceProvider       *string               `json:"service_provider,omitempty"`
	DataCenter            *string               `json:"data_center,omitempty"`
	DataCenterZone        *string               `json:"data_center_zone,omitempty"`
	Namespace             *string               `json:"namespace,omitempty"` // Only used in Container Workloads
	VulnerabilitySummary  *VulnerabilitySummary `json:"vulnerability_summary,omitempty"`
	ExternalDataReference *string               `json:"external_data_reference,omitempty"`
	ExternalDataSet       *string               `json:"external_data_set,omitempty"`
	CreatedAt             string                `json:"created_at,omitempty"`
	CreatedBy             *Href                 `json:"created_by,omitempty"`
	DeleteType            string                `json:"delete_type,omitempty"`
	Deleted               *bool                 `json:"deleted,omitempty"`
	DeletedAt             string                `json:"deleted_at,omitempty"`
	DeletedBy             *Href                 `json:"deleted_by,omitempty"`
	UpdatedAt             string                `json:"updated_at,omitempty"`
	UpdatedBy             *Href                 `json:"updated_by,omitempty"`
}

// An Interface represent the network interface of a workload
// An interface can never be updated or created
type Interface struct {
	Name                  string `json:"name,omitempty"`
	FriendlyName          string `json:"friendly_name,omitempty"`
	Address               string `json:"address,omitempty"`
	CidrBlock             *int   `json:"cidr_block,omitempty"` // Pointer to handle /0 vs. no Cidr provided
	DefaultGatewayAddress string `json:"default_gateway_address,omitempty"`
	LinkState             string `json:"link_state,omitempty"`
}

// WkldServices represent the Services running on a Workload
type WkldServices struct {
	OpenServicePorts *[]OpenServicePort `json:"open_service_ports,omitempty"`
	UptimeSeconds    int                `json:"uptime_seconds,omitempty"`
	CreatedAt        string             `json:"created_at,omitempty"`
}

// OpenServicePorts represents open ports for a service running on a workload
type OpenServicePort struct {
	Address        string `json:"address,omitempty"`
	Package        string `json:"package,omitempty"`
	Port           int    `json:"port,omitempty"`
	ProcessName    string `json:"process_name,omitempty"`
	Protocol       int    `json:"protocol,omitempty"`
	User           string `json:"user,omitempty"`
	WinServiceName string `json:"win_service_name,omitempty"`
}

type VulnerabilitySummary struct {
	NumVulnerabilities         int                        `json:"num_vulnerabilities,omitempty"`
	MaxVulnerabilityScore      int                        `json:"max_vulnerability_score,omitempty"`
	VulnerabilityScore         int                        `json:"vulnerability_score,omitempty"`
	VulnerablePortExposure     int                        `json:"vulnerable_port_exposure,omitempty"`
	VulnerablePortWideExposure VulnerablePortWideExposure `json:"vulnerable_port_wide_exposure,omitempty"`
	VulnerabilityExposureScore int                        `json:"vulnerability_exposure_score,omitempty"`
}

type VulnerablePortWideExposure struct {
	Any    bool `json:"any"`
	IPList bool `json:"ip_list"`
}

// An Agent is an Agent on a Workload
type Agent struct {
	Href          string         `json:"href,omitempty"`
	ActivePceFqdn string         `json:"active_pce_fqdn,omitempty"`
	TargetPceFqdn string         `json:"target_pce_fqdn,omitempty"`
	Config        *Config        `json:"config,omitempty"`
	SecureConnect *SecureConnect `json:"secure_connect,omitempty"`
	Status        *Status        `json:"status,omitempty"`
	Hostname      string         `json:"hostname,omitempty"` // Added this for events
}

// Config represents the Configuration of an Agent on a Workload
type Config struct {
	LogTraffic               bool   `json:"log_traffic"`
	Mode                     string `json:"mode,omitempty"`
	SecurityPolicyUpdateMode string `json:"security_policy_update_mode,omitempty"`
	VisibilityLevel          string `json:"visibility_level,omitempty"`
}

// SecureConnect represents SecureConnect for an Agent on a Workload
type SecureConnect struct {
	MatchingIssuerName string `json:"matching_issuer_name,omitempty"`
}

// Status represents the Status of an Agent on a Workload
type Status struct {
	AgentHealth              *[]AgentHealth     `json:"agent_health,omitempty"`
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

// Unpair is the payload for using the API to unpair workloads.
type Unpair struct {
	Workloads      []Workload `json:"workloads"`
	IPTableRestore string     `json:"ip_table_restore"`
}

// BulkResponse is the data structure for the bulk response API
type BulkResponse struct {
	Href    string  `json:"href"`
	Status  string  `json:"status"`
	Token   string  `json:"token"`
	Message string  `json:"message"`
	Errors  []Error `json:"errors"`
}

type Error struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

type IncreaseTrafficUpdateReq struct {
	Workloads []Workload `json:"workloads"`
}

// GetWklds returns a slice of workloads from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value"
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetWklds(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("workloads", false, queryParameters, &p.WorkloadsSlice)
	if len(p.WorkloadsSlice) >= 500 {
		p.WorkloadsSlice = nil
		api, err = p.GetCollection("workloads", true, queryParameters, &p.WorkloadsSlice)
	}
	// Load the PCE with the returned workloads
	p.Workloads = make(map[string]Workload)
	for _, w := range p.WorkloadsSlice {
		p.Workloads[w.Href] = w
		if PtrToVal(w.Hostname) != "" {
			p.Workloads[*w.Hostname] = w
		}
		if PtrToVal(w.Name) != "" {
			p.Workloads[*w.Name] = w
		}
		if PtrToVal(w.ExternalDataReference) != "" && PtrToVal(w.ExternalDataSet) != "" {
			p.Workloads[*w.ExternalDataSet+*w.ExternalDataReference] = w
		}
	}
	return api, err
}

// GetContainerWklds returns a slice of container workloads from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetContainerWklds(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("container_workloads", false, queryParameters, &p.ContainerWorkloadsSlice)
	if len(p.ContainerWorkloadsSlice) >= 500 {
		p.ContainerWorkloadsSlice = nil
		api, err = p.GetCollection("container_workloads", true, queryParameters, &p.ContainerWorkloadsSlice)
	}
	p.ContainerWorkloads = make(map[string]Workload)
	for _, w := range p.ContainerWorkloadsSlice {
		p.ContainerWorkloads[w.Href] = w
		p.ContainerWorkloads[PtrToVal(w.Hostname)] = w
		p.ContainerWorkloads[PtrToVal(w.Name)] = w
	}
	return api, err
}

// GetWkldByHref returns the workload with a specific href
func (p *PCE) GetWkldByHref(href string) (wkld Workload, api APIResponse, err error) {
	api, err = p.GetHref(href, &wkld)
	return wkld, api, err
}

// GetWkldByHostname gets a workload based on the hostname.
// GetWkldByBostname calls GetWklds which will replace the workload slice and maps
// An empty workload is returned if there is no exact match.
func (p *PCE) GetWkldByHostname(hostname string) (wkld Workload, api APIResponse, err error) {
	a, err := p.GetWklds(map[string]string{"hostname": hostname})
	if err != nil {
		return wkld, api, err
	}
	for _, w := range p.WorkloadsSlice {
		if PtrToVal(w.Hostname) == hostname {
			return w, a, nil
		}
	}
	return wkld, api, err
}

// CreateWkld creates a new unmanaged workload in the Illumio PCE
func (p *PCE) CreateWkld(wkld Workload) (createdWkld Workload, api APIResponse, err error) {
	api, err = p.Post("workloads", &wkld, &createdWkld)
	return createdWkld, api, err
}

// IncreaseTrafficUpdateRate increases the VEN traffic update rate
func (p *PCE) IncreaseTrafficUpdateRate(wklds []Workload) (APIResponse, error) {
	// Create a slice of workloads with just the Href
	t := []Workload{}
	for _, w := range wklds {
		t = append(t, Workload{Href: w.Href})
	}
	inc := IncreaseTrafficUpdateReq{Workloads: t}

	// Run the post. There is no response so just use a any empty struct
	api, err := p.Post("workloads/set_flow_reporting_frequency", &inc, &IncreaseTrafficUpdateReq{})

	return api, err
}

// UpdateWorkload updates an existing workload in the Illumio PCE
// The provided workload struct must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateWkld(workload Workload) (APIResponse, error) {
	workload.SanitizePut()
	api, err := p.Put(&workload)
	return api, err
}

// ChangeLabel updates a workload struct with new label href.
// It does not call the Illumio API to update the workload in the PCE. Use pce.UpdateWorkload() or bulk update for that.
// The method returns the labelMapH in case it needs to create a new label.
func (w *Workload) ChangeLabel(pce PCE, targetKey, newValue string) (PCE, error) {
	var updatedLabels []Label
	var newLabel Label
	var err error
	var ok bool

	// Iterate through each of the workloads labels
	for _, l := range PtrToVal(w.Labels) {
		// If they key isn't the target key, we add it to the updated labels
		if pce.Labels[l.Href].Key != targetKey {
			updatedLabels = append(updatedLabels, Label{Href: l.Href})
		}
	}

	// If new label isn't blank, get it's href and attach to array
	if newValue == "" {
		w.Labels = &updatedLabels
		return pce, nil
	}

	// If our new label is not blank, we need to get it's href and add it to the array
	if newLabel, ok = pce.Labels[targetKey+newValue]; !ok {
		// If it doesn't exist, we create it and put it back into the label maps
		newLabel, _, err = pce.CreateLabel(Label{Key: targetKey, Value: newValue})
		if err != nil {
			return pce, err
		}
		pce.Labels[newLabel.Href] = newLabel
		pce.Labels[newLabel.Key+newLabel.Value] = newLabel
	}
	// Append the new label to our label slice
	updatedLabels = append(updatedLabels, Label{Href: newLabel.Href})

	w.Labels = &updatedLabels
	return pce, nil
}

// BulkWorkload takes a bulk action on an array of workloads.
// Method must be create, update, or delete
func (p *PCE) BulkWorkload(workloads []Workload, method string, stdoutLogs bool) ([]APIResponse, error) {
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
	apiURL, err := url.Parse("https://" + p.cleanFQDN() + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/workloads/bulk_" + method)
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
	if stdoutLogs {
		fmt.Printf("%s [INFO] - Bulk API actions happen in 1,000 workload chunks. %d %s calls will be required to process the %d workloads.\r\n", time.Now().Format("2006-01-02 15:04:05 "), numAPICalls, method, len(workloads))
	}

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
	for i, apiArray := range apiArrays {
		workloadsJSON, err := json.Marshal(apiArray)
		if err != nil {
			return apiResps, fmt.Errorf("bulk workload error - %s", err)
		}

		api, err := p.httpReq("PUT", apiURL.String(), workloadsJSON, false, map[string]string{"Content-Type": "application/json"})
		if stdoutLogs {
			fmt.Printf("%s [INFO] - API Call %d of %d - complete - status code %d.\r\n", time.Now().Format("2006-01-02 15:04:05 "), i+1, numAPICalls, api.StatusCode)
		}

		// Marshal JSON
		var bulkResp []BulkResponse
		json.Unmarshal([]byte(api.RespBody), &bulkResp)

		for _, b := range bulkResp {
			if method == "update" && b.Status != "updated" {
				api.Warnings = append(api.Warnings, fmt.Sprintf("%s returned a status of %s with a message of %s and a token of %s", b.Href, b.Status, b.Message, b.Token))
			}
			if method == "delete" {
				errorText := []string{}
				for _, e := range b.Errors {
					errorText = append(errorText, fmt.Sprintf("message: %s and token: %s", e.Message, e.Token))
				}
				api.Warnings = append(api.Warnings, fmt.Sprintf("%s returned errors: %s", b.Href, strings.Join(errorText, ";")))
			}
			if method == "create" && b.Status != "created" {
				api.Warnings = append(api.Warnings, fmt.Sprintf("workload creation attempt returned a %s status and a %s message", b.Status, b.Message))
			}
		}

		api.ReqBody = string(workloadsJSON)

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
	w.VulnerabilitySummary = nil

	// Managed workloads
	if w.GetMode() != "unmanaged" {
		w.DistinguishedName = nil
		w.Hostname = nil
		w.Interfaces = nil
		w.Online = nil
		w.OsDetail = nil
		w.OsID = nil
		w.PublicIP = nil
		w.Services = nil
		w.Agent.Status = nil
		w.Agent.SecureConnect = nil
		w.Agent.ActivePceFqdn = "" // For supercluster-paired workloads
		w.Agent.TargetPceFqdn = "" // For supercluster-paired workloads
		w.Agent.Config.SecurityPolicyUpdateMode = ""
		w.VEN = nil // The VEN is not updateable.
	}

	if PtrToVal(w.EnforcementMode) != "" {
		w.Agent = nil
	}

	// Replace Labels with Hrefs
	newLabels := &[]Label{}
	for _, l := range PtrToVal(w.Labels) {
		newLabel := Label{Href: l.Href}
		*newLabels = append(*newLabels, newLabel)
	}
	w.Labels = newLabels

}

// SanitizePut removes the necessary properties to update a workload.
func (w *Workload) SanitizePut() {
	w.SanitizeBulkUpdate()
}

// GetLabelByKey returns the label object based on the provided key and label map
// A blank label is return if the label key is not used on the workload
func (w *Workload) GetLabelByKey(key string, labelMap map[string]Label) Label {
	if w.Labels == nil {
		return Label{}
	}
	for _, l := range *w.Labels {
		if strings.EqualFold(labelMap[l.Href].Key, key) {
			return labelMap[l.Href]
		}
	}
	return Label{}
}

// GetAppGroup returns the app group string of a workload in the format of App | Env.
// If the workload does not have an app or env label, "NO APP GROUP" is returned.
// Use GetAppGroupL to include the loc label in the app group.
func (w *Workload) GetAppGroup(labelMap map[string]Label) string {
	if w.GetLabelByKey("app", labelMap).Href == "" || w.GetLabelByKey("env", labelMap).Href == "" {
		return "NO APP GROUP"
	}

	return fmt.Sprintf("%s | %s", w.GetLabelByKey("app", labelMap).Value, w.GetLabelByKey("env", labelMap).Value)
}

// GetAppGroupL returns the app group string of a workload in the format of App | Env | Loc.
// If the workload does not have an app, env, or loc label, "NO APP GROUP" is returned.
// Use GetAppGroup to only use app and env in App Group.
func (w *Workload) GetAppGroupL(labelMap map[string]Label) string {
	if w.GetLabelByKey("app", labelMap).Href == "" || w.GetLabelByKey("env", labelMap).Href == "" || w.GetLabelByKey("loc", labelMap).Href == "" {
		return "NO APP GROUP"
	}

	return fmt.Sprintf("%s | %s | %s", w.GetLabelByKey("app", labelMap).Value, w.GetLabelByKey("env", labelMap).Value, w.GetLabelByKey("loc", labelMap).Value)
}

// GetMode returns the mode of the workloads.
// The returned value in 20.2 and newer PCEs will be unmanaged, idle, visibility_only, full, or selective.
// For visibility levels, use the w.GetVisibilityLevel() method.
//
// The returned value in 20.1 and lower PCEs will be unmanaged, idle, build, test, enforced-no, enforced-low, enforced-high.
// The enforced options represent no logging, low details, and high detail.
func (w *Workload) GetMode() string {
	spn := ""
	if w.ServicePrincipalName != nil {
		spn = *w.ServicePrincipalName
	}

	// Covers 20.2+ with the new API structure for VEN and enforcement_mode
	if PtrToVal(w.EnforcementMode) != "" {
		if (w.VEN == nil || w.VEN.Href == "") && spn == "" {
			return "unmanaged"
		}
		return PtrToVal(w.EnforcementMode)
	}

	// Covers prior to 20.2 when the API switched to enforcement_mode
	if (w.Agent == nil || w.Agent.Href == "") && spn == "" {
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
	if w.Agent.Config.Mode == "idle" {
		return "idle"
	}
	return "unk"

}

// SetMode adjusts the workload to reflect the assigned mode.
// Nothing is changed in the PCE. To reflect the change in the PCE use SetMode method followed by PCE.UpdateWorkload() method.
//
// Valid options in 20.2 and newer PCEs are idle, visibility_only, full, and selective.
// For visibility levels, use the w.SetVisibilityLevel() method.
//
// Valid options in 20.1 and lower PCEs are idle, build, test, enforced-no, enforced-low, enforced-high.
// The enforced options represent no logging, low details, and high detail.
func (w *Workload) SetMode(m string) error {

	m = strings.ToLower(m)

	// If the VEN href is populated, use the new method and properties
	if w.VEN != nil && w.VEN.Href != "" && (m == "visibility_only" || m == "full" || m == "selective" || m == "idle") {
		w.EnforcementMode = &m
		return nil
	}

	// Old VEN status
	switch m {

	case "idle":
		if w.VEN != nil && w.VEN.Href != "" {
			w.EnforcementMode = Ptr("idle")
		} else {
			w.Agent.Config.Mode = "idle"
		}
	case "build":
		if w.VEN != nil && w.VEN.Href != "" {
			w.EnforcementMode = Ptr("visibility_only")
			if err := w.SetVisibilityLevel("flow_summary"); err != nil {
				return err
			}
		} else {
			w.Agent.Config.Mode = "illuminated"
			w.Agent.Config.LogTraffic = false
		}

	case "test":
		if w.VEN != nil && w.VEN.Href != "" {
			w.EnforcementMode = Ptr("visibility_only")
			if err := w.SetVisibilityLevel("flow_summary"); err != nil {
				return err
			}
		} else {
			w.Agent.Config.Mode = "illuminated"
			w.Agent.Config.LogTraffic = true
		}

	case "enforced-no":
		if w.VEN != nil && w.VEN.Href != "" {
			w.EnforcementMode = Ptr("full")
			if err := w.SetVisibilityLevel("flow_off"); err != nil {
				return err
			}
		} else {
			w.Agent.Config.Mode = "enforced"
			w.Agent.Config.VisibilityLevel = "flow_off"
			w.Agent.Config.LogTraffic = false
		}

	case "enforced-low":
		if w.VEN != nil && w.VEN.Href != "" {
			w.EnforcementMode = Ptr("full")
			if err := w.SetVisibilityLevel("flow_drops"); err != nil {
				return err
			}
		} else {
			w.Agent.Config.Mode = "enforced"
			w.Agent.Config.VisibilityLevel = "flow_drops"
			w.Agent.Config.LogTraffic = true
		}

	case "enforced-high":
		if w.VEN != nil && w.VEN.Href != "" {
			w.EnforcementMode = Ptr("full")
			if err := w.SetVisibilityLevel("flow_summary"); err != nil {
				return err
			}
		} else {
			w.Agent.Config.Mode = "enforced"
			w.Agent.Config.VisibilityLevel = "flow_summary"
			w.Agent.Config.LogTraffic = true
		}

	default:
		return fmt.Errorf("%s is not a valid mode. See SetMode documentation for valid modes", m)

	}
	return nil
}

// SetVisibilityLevel adjusts the workload to reflect the assigned visibility level.
// Nothing is changed in the PCE. To reflect the change in the PCE use SetVisibilityLevel method followed by PCE.UpdateWorkload() method.
//
// Valid options in 20.2 and newer PCEs are flow_summary (blocked_allowed), flow_drops (blocked), flow_off (off), or enhanced_data_collection. The options in paranthesis are the UI values. Both are acceptable.
//
// 20.1 PCEs and lower do not use this method.
func (w *Workload) SetVisibilityLevel(v string) error {
	v = strings.ToLower(v)

	if v == "blocked_allowed" {
		v = "flow_summary"
	}
	if v == "blocked" {
		v = "flow_drops"
	}
	if v == "off" {
		v = "flow_off"
	}

	if v != "flow_summary" && v != "flow_drops" && v != "flow_off" && v != "enhanced_data_collection" {
		return fmt.Errorf("%s is not a valid visibility_level. See SetVisibilityLevel documentation for valid levels", v)
	}

	w.VisibilityLevel = Ptr(v)
	return nil
}

// GetVisibilityLevel returns unmanaged, blocked_allowed, blocked, or off.
func (w *Workload) GetVisibilityLevel() string {

	if w.GetMode() == "unmanaged" {
		return "unmanaged"
	}

	switch PtrToVal(w.VisibilityLevel) {
	case "flow_summary":
		return "blocked_allowed"
	case "flow_drops":
		return "blocked"
	case "flow_off":
		return "off"
	default:
		return PtrToVal(w.VisibilityLevel)
	}
}

// GetID returns the ID from the Href of an Agent
func (a *Agent) GetID() string {
	x := strings.Split(a.Href, "/")
	return x[len(x)-1]
}

// WorkloadUpgrade upgrades the VEN version on the workload
func (p *PCE) WorkloadUpgrade(wkldHref, targetVersion string) (APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + p.cleanFQDN() + ":" + strconv.Itoa(p.Port) + "/api/v2" + wkldHref + "/upgrade")
	if err != nil {
		return APIResponse{}, fmt.Errorf("upgrade workload - %s", err)
	}

	// Call the API
	api, err := p.httpReq("POST", apiURL.String(), json.RawMessage(fmt.Sprintf("{\"release\": \"%s\"}", targetVersion)), false, map[string]string{"Content-Type": "application/json"})
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
	apiURL, err := url.Parse("https://" + p.cleanFQDN() + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/workloads/unpair")
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
		api, err := p.httpReq("PUT", apiURL.String(), payload, false, map[string]string{"Content-Type": "application/json"})
		api.ReqBody = string(payload)
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
	for _, i := range PtrToVal(w.Interfaces) {
		if i.DefaultGatewayAddress != "" {
			return i.DefaultGatewayAddress
		}
	}
	return "NA"
}

// GetIPWithDefaultGW returns the IP address of the interface that has the default gateway
// If the workload does not have a default gateway (many unmanaged workloads), it will return "NA"
func (w *Workload) GetIPWithDefaultGW() string {
	for _, i := range PtrToVal(w.Interfaces) {
		if i.DefaultGatewayAddress != "" {
			return i.Address
		}
	}
	return "NA"
}

func (w *Workload) GetIsPWithDefaultGW() (ipAddresses []string) {
	for _, i := range PtrToVal(w.Interfaces) {
		if i.DefaultGatewayAddress != "" {
			ipAddresses = append(ipAddresses, i.Address)
		}
	}
	return ipAddresses
}

// GetNetMaskWithDefaultGW returns the netmask of the ip address that has the default gateway
// If the workload does not have a default gateway (many unmanaged workloads), it will return "NA"
func (w *Workload) GetNetMaskWithDefaultGW() string {
	for _, i := range PtrToVal(w.Interfaces) {
		if i.DefaultGatewayAddress != "" {
			return w.GetNetMask(i.Address)
		}
	}
	return "NA"
}

// GetNetworkWithDefaultGateway returns the CIDR notation of the network of the interface with the default gateway.
// If the workload does not have a default gateway (many unmanaged workloads), it will return "NA"
func (w *Workload) GetNetworkWithDefaultGateway() string {
	for _, i := range PtrToVal(w.Interfaces) {
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
	for _, i := range PtrToVal(w.Interfaces) {
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
	for _, i := range PtrToVal(w.Interfaces) {
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
	for _, i := range PtrToVal(w.Interfaces) {
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
	for _, i := range PtrToVal(w.Interfaces) {
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

// WorkloadQueryLabelParameter takes [][]string (example for after parsing a CSV). The first slice must be the label key headers (e.g., role, app, env, bu, etc.)
// Returns the query parameter for those labels.
// Each inner slice is an "AND" query
// The slices are put together using "OR"
// The PCE must be loaded with the labels
func (p *PCE) WorkloadQueryLabelParameter(labelSlices [][]string) (queryParameter string, err error) {

	// Find the headers
	headers := make(map[int]string)
	for i, header := range labelSlices[0] {
		headers[i] = header
	}

	// Iterate through each entry
	outer := []string{}
	for row, dataSet := range labelSlices {
		// Skip the first row
		if row == 0 {
			continue
		}

		// Iterate through each row
		inner := []string{}
		for column, csvValue := range dataSet {
			// If the value is blank, continue
			if csvValue == "" {
				continue
			}
			// If the label exists append it to the inner. If it does not exist, return an error
			if label, ok := p.Labels[headers[column]+csvValue]; ok {
				inner = append(inner, fmt.Sprintf("\"%s\"", label.Href))
			} else if label, ok := p.Labels[csvValue]; ok {
				inner = append(inner, fmt.Sprintf("\"%s\"", label.Href))
			} else {
				return "", fmt.Errorf("line %d - %s does not exist as a %s label", row+1, csvValue, headers[column])
			}
		}
		// Append to the outer
		outer = append(outer, fmt.Sprintf("[%s]", strings.Join(inner, ",")))
	}

	return fmt.Sprintf("[%s]", strings.Join(outer, ",")), nil
}
