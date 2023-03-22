package illumioapi

// Vulnerabilities are part of vulnerability maps.
// They are never created or updated.
type Vulnerability struct {
	Href        string   `json:"href,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Score       int      `json:"score,omitempty"`
	CveIds      []string `json:"cve_ids,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	CreatedBy   *Href    `json:"created_by,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
	UpdatedBy   *Href    `json:"updated_by,omitempty"`
}

// VulnerabilityReport are part of vulnerability maps.
// They are never created or updated.
type VulnerabilityReport struct {
	Href               string   `json:"href,omitempty"`
	Name               string   `json:"name,omitempty"`
	Authoritative      bool     `json:"authoritative,omitempty"`
	NumVulnerabilities int      `json:"num_vulnerabilities,omitempty"`
	ReportType         string   `json:"report_type,omitempty"`
	ScannedIps         []string `json:"scanned_ips,omitempty"`
	CreatedAt          string   `json:"created_at,omitempty"`
	CreatedBy          *Href    `json:"created_by,omitempty"`
	UpdatedAt          string   `json:"updated_at,omitempty"`
	UpdatedBy          *Href    `json:"updated_by,omitempty"`
}

// GetVulns returns a slice of vulnerabilities from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetVulns(queryParameters map[string]string) (vulns []Vulnerability, api APIResponse, err error) {
	api, err = p.GetCollection("vulnerabilities", false, queryParameters, &vulns)
	if len(vulns) >= 500 {
		vulns = nil
		api, err = p.GetCollection("vulnerabilities", true, queryParameters, &vulns)
	}
	return vulns, api, err
}

// GetVulnReports returns a slice of vulnerabilities from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetVulnReports(queryParameters map[string]string) (vulnReports []VulnerabilityReport, api APIResponse, err error) {
	api, err = p.GetCollection("vulnerability_reports", false, queryParameters, &vulnReports)
	if len(vulnReports) >= 500 {
		vulnReports = nil
		api, err = p.GetCollection("vulnerability_reports", true, queryParameters, &vulnReports)
	}
	return vulnReports, api, err
}
