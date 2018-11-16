package illumioapi

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
)

// ProductVersion represents the version of the product
type ProductVersion struct {
	Build           int    `json:"build,omitempty"`
	EngineeringInfo string `json:"engineering_info,omitempty"`
	LongDisplay     string `json:"long_display,omitempty"`
	ReleaseInfo     string `json:"release_info,omitempty"`
	ShortDisplay    string `json:"short_display,omitempty"`
	Version         string `json:"version,omitempty"`
}

// UserLogin represents a user logging in via password to get a session key
type UserLogin struct {
	AuthUsername                string          `json:"auth_username,omitempty"`
	FullName                    string          `json:"full_name,omitempty"`
	Href                        string          `json:"href,omitempty"`
	InactivityExpirationMinutes int             `json:"inactivity_expiration_minutes,omitempty"`
	LastLoginIPAddress          string          `json:"last_login_ip_address,omitempty"`
	LastLoginOn                 string          `json:"last_login_on,omitempty"`
	ProductVersion              *ProductVersion `json:"product_version,omitempty"`
	SessionToken                string          `json:"session_token,omitempty"`
	TimeZone                    string          `json:"time_zone,omitempty,omitempty"`
	Type                        string          `json:"type,omitempty"`
}

// Authentication represents the response of the Authenticate API
type Authentication struct {
	AuthToken string `json:"auth_token"`
}

// Authenticate produces a temporary auth token
func Authenticate(pce PCE, username, password string) (Authentication, error) { // username/password are separate from user/key

	var api APIResponse
	var err error
	var auth Authentication

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/login_users/authenticate")
	if err != nil {
		return auth, fmt.Errorf("authenticate error - %s", err)
	}
	q := apiURL.Query()
	q.Set("pce_fqdn", pce.FQDN)
	apiURL.RawQuery = q.Encode()

	// Call the API - Use a PCE object since that's what apicall expects
	api, err = apicall("POST", apiURL.String(), PCE{User: username, Key: password}, nil, false)
	if err != nil {
		return auth, fmt.Errorf("authenticate error - %s", err)
	}

	// Marshal the response
	json.Unmarshal([]byte(api.RespBody), &auth)

	return auth, nil
}

// Login takes an auth token and returns a session token
func Login(pce PCE, authToken string) (UserLogin, error) {
	var login UserLogin

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/users/login")
	if err != nil {
		return login, fmt.Errorf("login error - %s", err)
	}

	// Create HTTP client and request
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	// client := http.Client{}
	req, err := http.NewRequest("GET", apiURL.String(), nil)
	if err != nil {
		return login, fmt.Errorf("login error - %s", err)
	}

	// Set basic authentication and headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Token token="+authToken)

	// Make HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return login, fmt.Errorf("login error - %s", err)
	}

	// Process response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return login, fmt.Errorf("login error - %s", err)
	}

	// Put relevant response info into struct
	json.Unmarshal(data, &login)

	return login, nil

}
