package illumioapi

import "errors"

// CompatibilityReport is available in idle workloads.
// A CompatibilityReport is never created or updated.
type CompatibilityReport struct {
	Results       *Results `json:"results"`
	LastUpdatedAt string   `json:"last_updated_at"`
	QualifyStatus string   `json:"qualify_status"`
}

// Results contain a lists of compatibility report qualifying tests
type Results struct {
	QualifyTests *[]QualifyTest `json:"qualify_tests"`
}

// A QualifyTest is a test run by the compatibility check
type QualifyTest struct {
	Status                    string      `json:"status"`
	IpsecServiceEnabled       interface{} `json:"ipsec_service_enabled"`
	Ipv4ForwardingEnabled     interface{} `json:"ipv4_forwarding_enabled"`
	Ipv4ForwardingPktCnt      interface{} `json:"ipv4_forwarding_pkt_cnt"`
	IptablesRuleCnt           interface{} `json:"iptables_rule_cnt"`
	Ipv6GlobalScope           interface{} `json:"ipv6_global_scope"`
	Ipv6ActiveConnCnt         interface{} `json:"ipv6_active_conn_cnt"`
	IP6TablesRuleCnt          interface{} `json:"ip6tables_rule_cnt"`
	RoutingTableConflict      interface{} `json:"routing_table_conflict"`
	IPv6Enabled               interface{} `json:"IPv6_enabled"`
	UnwantedNics              interface{} `json:"Unwanted_nics"`
	GroupPolicy               interface{} `json:"Group_policy"`
	RequiredPackagesInstalled interface{} `json:"required_packages_installed"`
	RequiredPackagesMissing   *[]string   `json:"required_packages_missing"`
}

// GetCompatibilityReport returns the compatibility report for a VEN
func (p *PCE) GetCompatibilityReport(w Workload) (cr CompatibilityReport, api APIResponse, err error) {
	// Start with a blank href
	href := ""

	// If the VEN is not nil and it has a VEN href, use that
	if w.VEN != nil && w.VEN.Href != "" {
		href = w.VEN.Href
	} else if w.Agent != nil && w.Agent.Href != "" {
		href = w.Agent.Href
	}

	// If the href is still blank, return an error
	if href == "" {
		return cr, api, errors.New("no ven or agent href")
	}

	api, err = p.GetHref(href+"/compatibility_report", &cr)
	return cr, api, err
}
