package illumioapi

import (
	"fmt"
	"net/url"
	"strconv"
)

// DeleteHref deletes an existing object in the PCE based on its href.
func DeleteHref(pce PCE, href string) (APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1" + href)
	if err != nil {
		return api, fmt.Errorf("delete href - %s", err)
	}

	// Call the API
	api, err = apicall("DELETE", apiURL.String(), pce, nil, false)
	if err != nil {
		return api, fmt.Errorf("delete href - %s", err)
	}

	return api, nil
}
