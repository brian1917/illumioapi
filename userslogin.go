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

// getAuthToken is a private method that produces a temporary auth token for a valid username (email) and password.
// The pce instance must have a FQDN and port
func (p *PCE) getAuthToken(username, password string) (Authentication, APIResponse, error) {

	var api APIResponse
	var err error
	var auth Authentication

	// Build the API URL
	fqdn := pceSanitization(p.FQDN)
	if p.FQDN == "poc1.illum.io" || p.FQDN == "scp1.illum.io" || p.FQDN == "scp2.illum.io" || p.FQDN == "scp3.illum.io" || p.FQDN == "scp4.illum.io" || p.FQDN == "scp5.illum.io" || p.FQDN == "sca1.illum.io" || p.FQDN == "sca2.illum.io" {
		fqdn = "login.illum.io"
	}
	if p.FQDN == "xpress1.ilabs.io" {
		fqdn = "loginpce-dfdev1.ilabs.io"
	}
	apiURL, err := url.Parse("https://" + fqdn + ":" + strconv.Itoa(p.Port) + "/api/v2/login_users/authenticate")
	if err != nil {
		return auth, api, fmt.Errorf("authenticate error - %s", err)
	}
	q := apiURL.Query()
	q.Set("pce_fqdn", p.FQDN)
	apiURL.RawQuery = q.Encode()

	// Call the API - Use a PCE object since that's what apicall expects
	api, err = apicall("POST", apiURL.String(), PCE{DisableTLSChecking: p.DisableTLSChecking, User: username, Key: password}, nil, false)
	if err != nil {
		return auth, api, fmt.Errorf("authenticate error - %s", err)
	}

	// Marshal the response
	json.Unmarshal([]byte(api.RespBody), &auth)

	return auth, api, nil
}

// login is a private method that takes an auth token and returns UserLogin struct with a session token
// If the authToken is blank, the PCE struct must have API user and secret key and will get user information.
func (p *PCE) login(authToken string) (UserLogin, APIResponse, error) {
	var login UserLogin
	var response APIResponse

	// Check if we have either authToken or API user and key
	if authToken == "" && (p.User == "" || p.Key == "") {
		return login, response, fmt.Errorf("either auth token or PCE User and Key must be provided")
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/users/login")
	if err != nil {
		return login, response, fmt.Errorf("login error - %s", err)
	}

	// Create HTTP client and request
	client := &http.Client{}
	if p.DisableTLSChecking {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}

	req, err := http.NewRequest("GET", apiURL.String(), nil)
	if err != nil {
		return login, response, fmt.Errorf("login error - %s", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// If auth token is provided, set header. If auth token is empty, set user/key to receive org info
	if authToken != "" {
		req.Header.Set("Authorization", "Token token="+authToken)
	} else {
		req.SetBasicAuth(p.User, p.Key)
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

// Login authenticates to the PCE.
// Login will populate the User, Key, and Org fields in the PCE instance.
// Login will use a temporary session token that expires after 10 minutes.
func (p *PCE) Login(user, password string) (UserLogin, []APIResponse, error) {

	var apiResps []APIResponse

	auth, a, err := p.getAuthToken(user, password)
	apiResps = append(apiResps, a)
	if err != nil {
		return UserLogin{}, apiResps, fmt.Errorf("Error - Authenticating to PCE - %s", err)
	}
	login, a, err := p.login(auth.AuthToken)
	apiResps = append(apiResps, a)
	if err != nil {
		return login, apiResps, fmt.Errorf("Error - Logging in to PCE - %s", err)
	}
	p.User = login.AuthUsername
	p.Key = login.SessionToken
	p.Org = login.Orgs[0].ID

	return login, apiResps, nil
}

// LoginAPIKey authenticates to the PCE.
// Login will populate the User, Key, and Org fields in the PCE instance.
// LoginAPIKey will create a permanent API Key with the provided name and description fields.
func (p *PCE) LoginAPIKey(user, password, name, desc string) (UserLogin, []APIResponse, error) {

	login, a, err := p.Login(user, password)
	if err != nil {
		return login, a, fmt.Errorf("LoginAPIKey - %s", err)
	}

	apiURL, err := url.Parse("https://" + p.FQDN + ":" + strconv.Itoa(p.Port) + "/api/v2/" + login.Href + "/api_keys")
	if err != nil {
		return login, a, fmt.Errorf("LoginAPIKey - %s", err)
	}

	// Create payload
	postJSON, err := json.Marshal(APIKey{Name: name, Description: desc})
	if err != nil {
		return login, a, fmt.Errorf("LoginAPIKey - %s", err)
	}

	// Call the API
	apiResp, err := apicall("POST", apiURL.String(), *p, postJSON, false)
	if err != nil {
		return login, append(a, apiResp), fmt.Errorf("LoginAPIKey - %s", err)
	}

	// Marshal the response
	var apiKey APIKey
	json.Unmarshal([]byte(apiResp.RespBody), &apiKey)

	p.User = apiKey.AuthUsername
	p.Key = apiKey.Secret

	return login, append(a, apiResp), nil

}

// GetAllAPIKeys gets all the APIKeys associated with a user
func (p *PCE) GetAllAPIKeys(userHref string) ([]APIKey, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + p.FQDN + ":" + strconv.Itoa(p.Port) + "/api/v2" + userHref + "/api_keys")
	if err != nil {
		return []APIKey{}, APIResponse{}, fmt.Errorf("GetAllAPIKeys - %s", err)
	}

	// Call the API
	apiResp, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return []APIKey{}, apiResp, fmt.Errorf("GetAllAPIKeys - %s", err)
	}

	// Marshal the response
	var apiKeys []APIKey
	json.Unmarshal([]byte(apiResp.RespBody), &apiKeys)

	return apiKeys, apiResp, nil

}
