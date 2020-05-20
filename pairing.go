package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// PairingProfile represents a pairing profile in the Illumio PCE
type PairingProfile struct {
	AllowedUsesPerKey     string     `json:"allowed_uses_per_key,omitempty"`
	AppLabelLock          bool       `json:"app_label_lock"`
	CreatedAt             string     `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy `json:"created_by,omitempty"`
	Description           string     `json:"description,omitempty"`
	Enabled               bool       `json:"enabled"`
	EnvLabelLock          bool       `json:"env_label_lock"`
	ExternalDataReference string     `json:"external_data_reference,omitempty"`
	ExternalDataSet       string     `json:"external_data_set,omitempty"`
	Href                  string     `json:"href,omitempty,omitempty"`
	IsDefault             bool       `json:"is_default,omitempty"`
	KeyLifespan           string     `json:"key_lifespan,omitempty"`
	Labels                []*Label   `json:"labels,omitempty"`
	LastPairingAt         string     `json:"last_pairing_at,omitempty"`
	LocLabelLock          bool       `json:"loc_label_lock"`
	LogTraffic            bool       `json:"log_traffic"`
	LogTrafficLock        bool       `json:"log_traffic_lock"`
	Mode                  string     `json:"mode,omitempty"`
	ModeLock              bool       `json:"mode_lock"`
	Name                  string     `json:"name,omitempty"`
	RoleLabelLock         bool       `json:"role_label_lock"`
	TotalUseCount         int        `json:"total_use_count,omitempty"`
	UpdatedAt             string     `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy `json:"updated_by,omitempty,omitempty"`
	VisibilityLevel       string     `json:"visibility_level,omitempty"`
	VisibilityLevelLock   bool       `json:"visibility_level_lock"`
}

// PairingKey represents a VEN pairing key
type PairingKey struct {
	ActivationCode string `json:"activation_code,omitempty"`
}

// GetAllPairingProfiles gets all pairing profiles in the Illumio PCE.
func (p *PCE) GetAllPairingProfiles() ([]PairingProfile, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/pairing_profiles")
	if err != nil {
		return nil, APIResponse{}, err
	}

	// Call the API
	api, err := apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, err
	}

	// Unmarshal response to struct
	var pairingProfiles []PairingProfile
	json.Unmarshal([]byte(api.RespBody), &pairingProfiles)

	// Check if we need to re-run with async
	if len(pairingProfiles) >= 500 {
		api, err = apicall("GET", apiURL.String(), *p, nil, true)
		if err != nil {
			return nil, api, fmt.Errorf("get all pairing profiles - %s", err)
		}

		// Unmarshal response to struct
		var asyncPairingProfiles []PairingProfile
		json.Unmarshal([]byte(api.RespBody), &asyncPairingProfiles)

		return asyncPairingProfiles, api, nil
	}

	// Return if less than 500
	return pairingProfiles, api, nil
}

// CreatePairingProfile creates a new pairing profile in the Illumio PCE.
func (p *PCE) CreatePairingProfile(pairingProfile PairingProfile) (APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/pairing_profiles")
	if err != nil {
		return APIResponse{}, err
	}

	// Create the Payload
	pairProfileJSON, err := json.Marshal(pairingProfile)
	if err != nil {
		return APIResponse{}, err
	}

	// Call the API
	api, err := apicall("POST", apiURL.String(), *p, pairProfileJSON, false)
	if err != nil {
		return api, err
	}

	return api, nil
}

// CreatePairingKey creates a pairing key from a pairing profile.
func (p *PCE) CreatePairingKey(pairingProfile PairingProfile) (PairingKey, APIResponse, error) {

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2" + pairingProfile.Href + "/pairing_key")
	if err != nil {
		return PairingKey{}, APIResponse{}, err
	}

	// Call the API
	api, err := apicall("POST", apiURL.String(), *p, []byte("{}"), false)
	if err != nil {
		return PairingKey{}, api, err
	}

	// Unmarshal response to struct
	var pairingKey PairingKey
	json.Unmarshal([]byte(api.RespBody), &pairingKey)

	return pairingKey, api, nil
}
