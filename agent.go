package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Agent represents an Illumio VEN
// type Agent struct {
// 	ActivePceFqdn   string   `json:"active_pce_fqdn,omitempty"`
// 	AgentVersion    string   `json:"agent_version,omitempty"`
// 	Description     string   `json:"description,omitempty"`
// 	Hostname        string   `json:"hostname,omitempty"`
// 	IPTablesSaved   bool     `json:"ip_tables_saved,omitempty"`
// 	Labels          []*Label `json:"labels,omitempty"`
// 	LastHeartbeatOn string   `json:"last_heartbeat_on,omitempty"`
// 	LogTraffic      bool     `json:"log_traffic,omitempty"`
// 	Mode            string   `json:"mode,omitempty"`
// 	Name            string   `json:"name,omitempty"`
// 	Online          bool     `json:"online,omitempty"`
// 	OsDetail        string   `json:"os_detail,omitempty"`
// 	OSID            string   `json:"os_id,omitempty"`
// 	PublicIP        string   `json:"public_ip,omitempty"`
// 	TargetPceFqdn   string   `json:"target_pce_fqdn,omitempty"`
// 	UID             string   `json:"uid,omitempty"`
// 	UptimeSeconds   string   `json:"uptime_seconds,omitempty"`
// }

// CompatabilityReport is a compatibility report for a VEN in Idle status
type CompatabilityReport struct {
	LastUpdatedAt time.Time `json:"last_updated_at"`
	Results       Results   `json:"results"`
	QualifyStatus string    `json:"qualify_status"`
}
type QualifyTests struct {
	RequiredPackages          []string `json:"required_packages,omitempty"`
	RequiredPackagesInstalled bool     `json:"required_packages_installed,omitempty"`
	Status                    string   `json:"status,omitempty"`
	RequiredPackagesMissing   []string `json:"required_packages_missing,omitempty"`
	Ipv4ForwardingEnabled     string   `json:"ipv4_forwarding_enabled,omitempty"`
	Ipv4ForwardingPktCnt      int      `json:"ipv4_forwarding_pkt_cnt,omitempty"`
	IptablesRuleCnt           int      `json:"iptables_rule_cnt,omitempty"`
	Ipv6GlobalScope           string   `json:"ipv6_global_scope,omitempty"`
	Ipv6ActiveConnCnt         int      `json:"ipv6_active_conn_cnt,omitempty"`
	IP6TablesRuleCnt          int      `json:"ip6tables_rule_cnt,omitempty"`
}
type Results struct {
	QualifyTests []QualifyTests `json:"qualify_tests"`
}

// GetCompatabilityReport returns the compatability report for a VEN
func GetCompatabilityReport(pce PCE, w Workload) (CompatabilityReport, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2" + w.Agent.Href + "/compatibility_report")
	if err != nil {
		return CompatabilityReport{}, APIResponse{}, fmt.Errorf("get compatability report - building URL - %s", err)
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return CompatabilityReport{}, APIResponse{}, fmt.Errorf("get compatability report - calling API - %s", err)
	}

	var cr CompatabilityReport
	json.Unmarshal([]byte(api.RespBody), &cr)

	return cr, api, nil
}
