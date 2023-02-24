package illumioapi

import (
	"fmt"
)

// A Label represents an Illumio Label.
type Label struct {
	CreatedAt             string      `json:"created_at,omitempty"`
	CreatedBy             *CreatedBy  `json:"created_by,omitempty"`
	Deleted               bool        `json:"deleted,omitempty"`
	ExternalDataReference string      `json:"external_data_reference,omitempty"`
	ExternalDataSet       string      `json:"external_data_set,omitempty"`
	Href                  string      `json:"href,omitempty"`
	Key                   string      `json:"key,omitempty"`
	UpdatedAt             string      `json:"updated_at,omitempty"`
	UpdatedBy             *UpdatedBy  `json:"updated_by,omitempty"`
	Value                 string      `json:"value,omitempty"`
	LabelUsage            *LabelUsage `json:"usage,omitempty"`
}

// CreatedBy represents the CreatedBy property of an object
type CreatedBy struct {
	Href string `json:"href"`
}

// UpdatedBy represents the UpdatedBy property of an object
type UpdatedBy struct {
	Href string `json:"href"`
}

type LabelUsage struct {
	VirtualServer                     bool `json:"virtual_server"`
	LabelGroup                        bool `json:"label_group"`
	Ruleset                           bool `json:"ruleset"`
	StaticPolicyScopes                bool `json:"static_policy_scopes"`
	PairingProfile                    bool `json:"pairing_profile"`
	Permission                        bool `json:"permission"`
	Workload                          bool `json:"workload"`
	ContainerWorkload                 bool `json:"container_workload"`
	FirewallCoexistenceScope          bool `json:"firewall_coexistence_scope"`
	ContainersInheritHostPolicyScopes bool `json:"containers_inherit_host_policy_scopes"`
	ContainerWorkloadProfile          bool `json:"container_workload_profile"`
	BlockedConnectionRejectScope      bool `json:"blocked_connection_reject_scope"`
	EnforcementBoundary               bool `json:"enforcement_boundary"`
	LoopbackInterfacesInPolicyScopes  bool `json:"loopback_interfaces_in_policy_scopes"`
	VirtualService                    bool `json:"virtual_service"`
}

// GetLabels returns a slice of labels from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetLabels(queryParameters map[string]string) (labels []Label, api APIResponse, err error) {
	api, err = p.GetCollection("labels", false, queryParameters, &labels)
	if len(labels) >= 500 {
		labels = nil
		api, err = p.GetCollection("labels", true, queryParameters, &labels)
	}
	return labels, api, err
}

// GetLabelByKeyValue finds a label based on the key and value. A blank label is return if no exact match.
func (p *PCE) GetLabelByKeyValue(key, value string) (Label, APIResponse, error) {
	labels, api, err := p.GetLabels(map[string]string{"key": key, "value": value})
	for _, label := range labels {
		if label.Value == value {
			return label, api, err
		}
	}
	return Label{}, api, nil
}

// GetLabelbyHref returns a label based on the provided HREF.
func (p *PCE) GetLabelByHref(href string) (Label, APIResponse, error) {
	var label Label
	api, err := p.GetHref(href, &label)
	return label, api, err
}

// CreateLabel creates a new Label in the PCE.
func (p *PCE) CreateLabel(label Label) (createdLabel Label, api APIResponse, err error) {
	api, err = p.Post("labels", &label, &createdLabel)
	return createdLabel, api, err
}

// UpdateLabel updates an existing label in the PCE.
// The provided label must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateLabel(label Label) (APIResponse, error) {
	// Create a new label with just the fields that should be updated and the href
	l := Label{
		Href:                  label.Href,
		Value:                 label.Value,
		ExternalDataReference: label.ExternalDataReference,
		ExternalDataSet:       label.ExternalDataSet,
	}
	api, err := p.Put(&l)
	return api, err
}

// Credit for function to mxschmitt/golang-combinations
// All returns all combinations for a given string array.
// This is essentially a powerset of the given set except that the empty set is disregarded.
func combinations[T any](set []T) (subsets [][]T) {
	length := uint(len(set))

	// Go through all possible combinations of objects
	// from 1 (only first object in subset) to 2^length (all objects in subset)
	for subsetBits := 1; subsetBits < (1 << length); subsetBits++ {
		var subset []T

		for object := uint(0); object < length; object++ {
			// checks if object is contained in subset
			// by checking if bit 'object' is set in subsetBits
			if (subsetBits>>object)&1 == 1 {
				// add object to subset
				subset = append(subset, set[object])
			}
		}
		// add subset to subsets
		subsets = append(subsets, subset)
	}
	return subsets
}

// LabelsToRuleStructure takes a slice of labels and returns a slice of slices for how the labels would be organized as read by the PCE rule processing.
// For example {"A-ERP", "A-CRM", "E-PROD"} will return [{"A-ERP, E-PROD"}. {"A-CRM", "E-PROD"}]
func LabelsToRuleStructure(labels []Label) ([][]Label, error) {
	// Get all the unique keys
	keys := make(map[string]bool)
	for _, l := range labels {
		if l.Key == "" {
			return nil, fmt.Errorf("labels must have a key")
		}
		keys[l.Key] = true
	}

	// Get all combinations
	allCombinations := combinations(labels)

	// Create the keep list
	keep := [][]Label{}
entryLoop:
	for _, entry := range allCombinations {
		// Check to make sure only one of each label type
		labelKeyChecker := make(map[string]bool)
		for _, member := range entry {
			if _, exists := labelKeyChecker[member.Key]; exists {
				continue entryLoop
			}
			labelKeyChecker[member.Key] = true
		}
		// Check to make sure all label types
		if len(labelKeyChecker) == len(keys) {
			keep = append(keep, entry)
		}
	}
	return keep, nil
}
