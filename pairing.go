package illumioapi

import (
	"fmt"
	"strings"
)

// PairingProfile is a pairing profile in PCE.
type PairingProfile struct {
	Href                  string   `json:"href,omitempty"`
	Name                  string   `json:"name,omitempty"`
	VenType               string   `json:"ven_type,omitempty"`
	Description           *string  `json:"description,omitempty"`
	IsDefault             *bool    `json:"is_default,omitempty"`
	Enabled               *bool    `json:"enabled"`
	Mode                  string   `json:"mode,omitempty"`
	VisibilityLevel       string   `json:"visibility_level,omitempty"`
	Labels                *[]Label `json:"labels,omitempty"`
	AllowedUsesPerKey     string   `json:"allowed_uses_per_key,omitempty"`
	LogTraffic            *bool    `json:"log_traffic"`
	AppLabelLock          *bool    `json:"app_label_lock"`
	EnvLabelLock          *bool    `json:"env_label_lock"`
	LocLabelLock          *bool    `json:"loc_label_lock"`
	RoleLabelLock         *bool    `json:"role_label_lock"`
	ModeLock              *bool    `json:"mode_lock"`
	VisibilityLevelLock   *bool    `json:"visibility_level_lock"`
	LogTrafficLock        *bool    `json:"log_traffic_lock"`
	KeyLifespan           string   `json:"key_lifespan,omitempty"`
	TotalUseCount         int      `json:"total_use_count,omitempty"`
	ExternalDataReference *string  `json:"external_data_reference,omitempty"`
	ExternalDataSet       *string  `json:"external_data_set,omitempty"`
	LastPairingAt         string   `json:"last_pairing_at,omitempty"`
	CreatedAt             string   `json:"created_at,omitempty"`
	CreatedBy             *Href    `json:"created_by,omitempty"`
	UpdatedAt             string   `json:"updated_at,omitempty"`
	UpdatedBy             *Href    `json:"updated_by,omitempty"`
}

// PairingKey represents a VEN pairing key
type PairingKey struct {
	ActivationCode string `json:"activation_code,omitempty"`
}

// GetPairingProfiles returns a slice of pairing profiles from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetPairingProfiles(queryParameters map[string]string) (pairingProfiles []PairingProfile, api APIResponse, err error) {
	api, err = p.GetCollection("pairing_profiles", false, queryParameters, &pairingProfiles)
	if len(pairingProfiles) >= 500 {
		pairingProfiles = nil
		api, err = p.GetCollection("pairing_profiles", true, queryParameters, &pairingProfiles)
	}
	return pairingProfiles, api, err
}

// CreatePairingProfile creates a new pairing profile in the PCE.
func (p *PCE) CreatePairingProfile(pairingProfile PairingProfile) (createdPairingProfile PairingProfile, api APIResponse, err error) {
	api, err = p.Post("pairing_profiles", &pairingProfile, &createdPairingProfile)
	return createdPairingProfile, api, err
}

// CreatePairingKey creates a pairing key from a pairing profile.
func (p *PCE) CreatePairingKey(pairingProfile PairingProfile) (pairingKey PairingKey, api APIResponse, err error) {
	api, err = p.Post(strings.TrimPrefix(pairingProfile.Href, fmt.Sprintf("/orgs/%d/", p.Org))+"/pairing_key", &struct{}{}, &pairingKey)
	return pairingKey, api, err
}
