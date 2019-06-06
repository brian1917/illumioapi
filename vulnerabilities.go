package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Vulnerability represents a vulnerability in the Illumio PCE
type Vulnerability struct {
	CreatedAt   string     `json:"created_at,omitempty"`
	CreatedBy   *CreatedBy `json:"created_by,omitempty"`
	CveIds      []string   `json:"cve_ids,omitempty"`
	Description string     `json:"description,omitempty"`
	Href        string     `json:"href,omitempty"`
	Name        string     `json:"name,omitempty"`
	Score       int        `json:"score,omitempty"`
	UpdatedAt   string     `json:"updated_at,omitempty"`
	UpdatedBy   *UpdatedBy `json:"updated_by,omitempty"`
}

// VulnerabilityReport represents a vulnerability report in the Illumio PCE
type VulnerabilityReport struct {
	Authoritative      bool       `json:"authoritative,omitempty"`
	CreatedAt          string     `json:"created_at,omitempty"`
	CreatedBy          *CreatedBy `json:"created_by,omitempty"`
	Href               string     `json:"href,omitempty"`
	Name               string     `json:"name,omitempty"`
	NumVulnerabilities int        `json:"num_vulnerabilities,omitempty"`
	ReportType         string     `json:"report_type,omitempty"`
	ScannedIps         []string   `json:"scanned_ips,omitempty,omitempty"`
	UpdatedAt          string     `json:"updated_at,omitempty"`
	UpdatedBy          *UpdatedBy `json:"updated_by,omitempty"`
}

// GetAllVulns returns a slice of all Vulnerabilities in the Illumio PCE.
// The first call does not use the async option.
// If the response slice length is >=500, it is re-run enabling async.
func GetAllVulns(pce PCE) ([]Vulnerability, APIResponse, error) {
	var vulns []Vulnerability
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/vulnerabilities")
	if err != nil {
		return vulns, api, fmt.Errorf("get all vulnerabilities - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return vulns, api, fmt.Errorf("get all vulnerabilities - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &vulns)

	// If length is 500, re-run with async
	if len(vulns) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return vulns, api, fmt.Errorf("get all vulnerabilties - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &vulns)
	}

	return vulns, api, nil
}

// GetAllVulnReports returns a slice of all Vulnerability Reports in the Illumio PCE.
// The first call does not use the async option.
// If the response slice length is >=500, it is re-run enabling async.
func GetAllVulnReports(pce PCE) ([]VulnerabilityReport, APIResponse, error) {
	var vulnReports []VulnerabilityReport
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/orgs/" + strconv.Itoa(pce.Org) + "/vulnerability_reports")
	if err != nil {
		return vulnReports, api, fmt.Errorf("get all vulnerability reports - %s", err)
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return vulnReports, api, fmt.Errorf("get all vulnerability reports - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &vulnReports)

	// If length is 500, re-run with async
	if len(vulnReports) >= 500 {
		api, err = apicall("GET", apiURL.String(), pce, nil, true)
		if err != nil {
			return vulnReports, api, fmt.Errorf("get all vulnerability reports - %s", err)
		}

		// Unmarshal response to struct
		json.Unmarshal([]byte(api.RespBody), &vulnReports)
	}

	return vulnReports, api, nil
}
