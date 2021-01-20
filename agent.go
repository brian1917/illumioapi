package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// CompatibilityReport is a compatibility report for a VEN in Idle status
type CompatibilityReport struct {
	LastUpdatedAt time.Time `json:"last_updated_at"`
	Results       Results   `json:"results"`
	QualifyStatus string    `json:"qualify_status"`
}

// QualifyTest is part of compatibility report
type QualifyTest struct {
	Status                    string   `json:"status"`
	IpsecServiceEnabled       string   `json:"ipsec_service_enabled"` // Using a string to differentiate between false and empty
	Ipv4ForwardingEnabled     bool     `json:"ipv4_forwarding_enabled"`
	Ipv4ForwardingPktCnt      int      `json:"ipv4_forwarding_pkt_cnt"`
	IptablesRuleCnt           int      `json:"iptables_rule_cnt"`
	Ipv6GlobalScope           bool     `json:"ipv6_global_scope"`
	Ipv6ActiveConnCnt         int      `json:"ipv6_active_conn_cnt"`
	IP6TablesRuleCnt          int      `json:"ip6tables_rule_cnt"`
	RoutingTableConflict      bool     `json:"routing_table_conflict"`
	IPv6Enabled               bool     `json:"IPv6_enabled"`
	UnwantedNics              bool     `json:"Unwanted_nics"`
	GroupPolicy               bool     `json:"Group_policy"`
	RequiredPackagesInstalled string   `json:"required_packages_installed"` // Using a string to differentiate between false and empty
	RequiredPackagesMissing   []string `json:"required_packages_missing"`
}

// Results are the list of qualify tests
type Results struct {
	QualifyTests []QualifyTest `json:"qualify_tests"`
}

// GetCompatibilityReport returns the compatibility report for a VEN
func (p *PCE) GetCompatibilityReport(w Workload) (CompatibilityReport, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + w.Agent.Href + "/compatibility_report")
	if err != nil {
		return CompatibilityReport{}, APIResponse{}, fmt.Errorf("get compatibility report - building URL - %s", err)
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return CompatibilityReport{}, APIResponse{}, fmt.Errorf("get compatibility report - calling API - %s", err)
	}

	var cr CompatibilityReport
	json.Unmarshal([]byte(api.RespBody), &cr)

	return cr, api, nil
}
