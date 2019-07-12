package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Version represents the version of the PCE
type Version struct {
	Version      string `json:"version"`
	Build        int    `json:"build"`
	LongDisplay  string `json:"long_display"`
	ShortDisplay string `json:"short_display"`
}

// GetVersion returns the version of the PCE
func GetVersion(pce PCE) (Version, error) {
	var version Version

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v2/product_version")
	if err != nil {
		return Version{}, fmt.Errorf("get version - %s", err)
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), pce, nil, false)
	if err != nil {
		return Version{}, fmt.Errorf("get version - %s", err)
	}

	json.Unmarshal([]byte(api.RespBody), &version)

	return version, nil
}
