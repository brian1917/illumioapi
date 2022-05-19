package illumioapi

import (
	"encoding/json"
	"net/url"
	"strconv"
)

// GetHref returns the Illumio object with a specific href
func (p *PCE) GetHref(href string, response interface{}) (APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + href)
	if err != nil {
		return api, err
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return api, err
	}

	err = json.Unmarshal([]byte(api.RespBody), &response)
	return api, err
}
