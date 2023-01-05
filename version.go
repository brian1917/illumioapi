package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Version represents the version of the PCE
type Version struct {
	Version      string `json:"version"`
	Build        int    `json:"build"`
	LongDisplay  string `json:"long_display"`
	ShortDisplay string `json:"short_display"`
	Major        int
	Minor        int
	Patch        int
}

// GetVersion returns the version of the PCE
func (p *PCE) GetVersion() (version Version, api APIResponse, err error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + p.cleanFQDN() + ":" + strconv.Itoa(p.Port) + "/api/v2/product_version")
	if err != nil {
		return Version{}, api, fmt.Errorf("get version - %s", err)
	}

	// Call the API
	api, err = p.httpReq("GET", apiURL.String(), nil, false, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return Version{}, api, fmt.Errorf("get version - %s", err)
	}
	json.Unmarshal([]byte(api.RespBody), &version)

	// Process the versions
	numbers := strings.Split(version.Version, ".")
	version.Major, err = strconv.Atoi(numbers[0])
	if err != nil {
		return Version{}, api, fmt.Errorf("calculating major - %s", err)
	}
	if len(numbers) > 1 {
		version.Minor, err = strconv.Atoi(numbers[1])
		if err != nil {
			return Version{}, api, fmt.Errorf("calculating minor - %s", err)
		}
	}
	if len(numbers) > 2 {
		version.Patch, err = strconv.Atoi(numbers[2])
		if err != nil {
			return Version{}, api, fmt.Errorf("calculating patch - %s", err)
		}
	}
	p.Version = version

	return version, api, nil
}
