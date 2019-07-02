package illumioapi

import (
	"crypto/tls"
	"encoding/json"
	"errors"
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
	Orgs                        []*Org          `json:"orgs,omitempty"`
}

// Org is an an organization in a SaaS PCE
type Org struct {
	Href        string `json:"href"`
	DisplayName string `json:"display_name"`
	ID          int    `json:"org_id"`
}

// Authentication represents the response of the Authenticate API
type Authentication struct {
	AuthToken string `json:"auth_token"`
}

// APIKey represents an API Key
type APIKey struct {
	Href         string `json:"href,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
	AuthUsername string `json:"auth_username,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	Name         string `json:"name,omitempty"`
	Description  string `json:"description,omitempty"`
	Secret       string `json:"secret,omitempty"`
}

// Authenticate produces a temporary auth token for a valid username (email) and password
func Authenticate(pce PCE, username, password string) (Authentication, APIResponse, error) {

	var api APIResponse
	var err error
	var auth Authentication

	// Build the API URL
	fqdn := pceSanitization(pce.FQDN)
	if pce.FQDN == "poc1.illum.io" || pce.FQDN == "scp1.illum.io" {
		fqdn = "login.illum.io"
	}
	apiURL, err := url.Parse("https://" + fqdn + ":" + strconv.Itoa(pce.Port) + "/api/v1/login_users/authenticate")
	if err != nil {
		return auth, api, fmt.Errorf("authenticate error - %s", err)
	}
	q := apiURL.Query()
	q.Set("pce_fqdn", pce.FQDN)
	apiURL.RawQuery = q.Encode()

	// Call the API - Use a PCE object since that's what apicall expects
	api, err = apicall("POST", apiURL.String(), PCE{DisableTLSChecking: pce.DisableTLSChecking, User: username, Key: password}, nil, false)
	if err != nil {
		return auth, api, fmt.Errorf("authenticate error - %s", err)
	}

	// Marshal the response
	json.Unmarshal([]byte(api.RespBody), &auth)

	return auth, api, nil
}

// Login takes an auth token and returns a session token
func Login(pce PCE, authToken string) (UserLogin, APIResponse, error) {
	var login UserLogin
	var response APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/users/login")
	if err != nil {
		return login, response, fmt.Errorf("login error - %s", err)
	}

	// Create HTTP client and request
	client := &http.Client{}
	if pce.DisableTLSChecking == true {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequest("GET", apiURL.String(), nil)
	if err != nil {
		return login, response, fmt.Errorf("login error - %s", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// If auth token is provided, set header. If autho token is empty, set user/key to receive org info
	if authToken != "" {
		req.Header.Set("Authorization", "Token token="+authToken)
	} else {
		req.SetBasicAuth(pce.User, pce.Key)
	}

	// Make HTTP Request
	resp, err := client.Do(req)
	if err != nil {
		return login, response, fmt.Errorf("login error - %s", err)
	}

	// Process response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return login, response, fmt.Errorf("login error - %s", err)
	}

	// Put relevant response info into struct
	response.RespBody = string(data[:])
	response.StatusCode = resp.StatusCode
	response.Header = resp.Header
	response.Request = resp.Request

	// Check for a 200 response code
	if strconv.Itoa(resp.StatusCode)[0:1] != "2" {
		return login, response, errors.New("login error - http status code of " + strconv.Itoa(response.StatusCode))
	}

	// Put relevant response info into struct
	json.Unmarshal(data, &login)

	return login, response, nil

}

// PCEbuilder builds a PCE.
// User can be API User or email address. Password can be password or API Secret.
// PCEbuilder will find the org.
func PCEbuilder(fqdn, user, password string, port int, disableTLS bool) (PCE, error) {
	var pce PCE
	var org int

	// If the user string begins with "api_", we need to get the Org using the login api
	if user[:4] == "api_" {
		login, _, err := Login(PCE{FQDN: fqdn, User: user, Key: password, Port: port}, "")
		if err != nil {
			return pce, fmt.Errorf("Error logging into the PCE to get org ID - %s", err)
		}
		org = login.Orgs[0].ID

		// If it doesn't start with "api_", we need to authenticate and then login
	} else {
		auth, _, err := Authenticate(PCE{FQDN: fqdn, Port: port, DisableTLSChecking: disableTLS}, user, password)
		if err != nil {
			return pce, fmt.Errorf("Error - Authenticating to PCE - %s", err)
		}
		login, _, err := Login(PCE{FQDN: fqdn, Port: port, DisableTLSChecking: disableTLS}, auth.AuthToken)
		if err != nil {
			return pce, fmt.Errorf("Error - Logging in to PCE - %s", err)
		}
		user = login.AuthUsername
		password = login.SessionToken
		org = login.Orgs[0].ID
	}

	// Create the PCE
	pce = PCE{
		FQDN:               fqdn,
		Port:               port,
		Org:                org,
		User:               user,
		Key:                password,
		DisableTLSChecking: disableTLS}

	return pce, nil
}

// CreateAPIKey creates an returns an API Key
func CreateAPIKey(pce PCE, user, password, name, desc string) (PCE, APIResponse, error) {
	var apiKey APIKey
	var apiResp APIResponse

	auth, _, err := Authenticate(pce, user, password)
	if err != nil {
		return PCE{}, apiResp, fmt.Errorf("Error - Authenticating to PCE - %s", err)
	}
	login, _, err := Login(pce, auth.AuthToken)
	if err != nil {
		return PCE{}, apiResp, fmt.Errorf("Error - Logging in to PCE - %s", err)
	}

	apiURL, err := url.Parse("https://" + pce.FQDN + ":" + strconv.Itoa(pce.Port) + "/api/v2/" + login.Href + "/api_keys")
	if err != nil {
		return PCE{}, apiResp, fmt.Errorf("create api key error - %s", err)
	}

	pce.User = login.AuthUsername
	pce.Key = login.SessionToken
	pce.Org = login.Orgs[0].ID

	// Create payload
	postJSON, err := json.Marshal(APIKey{Name: name, Description: desc})
	if err != nil {
		return PCE{}, apiResp, fmt.Errorf("create api key - %s", err)
	}

	// Call the API
	apiResp, err = apicall("POST", apiURL.String(), pce, postJSON, false)
	if err != nil {
		return PCE{}, apiResp, fmt.Errorf("create api key error - %s", err)
	}

	// Marshal the response
	json.Unmarshal([]byte(apiResp.RespBody), &apiKey)

	pce.User = apiKey.AuthUsername
	pce.Key = apiKey.Secret

	return pce, apiResp, nil

}
