package illumioapi

import (
	"errors"
)

// ContainerWorkloadProfile is a Kubernetes namespace
type ContainerWorkloadProfile struct {
	Href            string   `json:"href,omitempty"`
	Name            *string  `json:"name"` // API expects null for name to remove it. Always sent.
	Namespace       string   `json:"namespace,omitempty"`
	Description     *string  `json:"description,omitempty"`
	Labels          *[]Label `json:"labels,omitempty"`
	EnforcementMode *string  `json:"enforcement_mode,omitempty"`
	VisibilityLevel *string  `json:"visibility_level,omitempty"`
	Managed         *bool    `json:"managed,omitempty"`
	Linked          *bool    `json:"linked,omitempty"`
	ClusterName     string   `json:"-"`
	CreatedAt       string   `json:"created_at,omitempty"`
	CreatedBy       *Href    `json:"created_by,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
	UpdatedBy       *Href    `json:"updated_by,omitempty"`
}

// GetContainerWkldProfiles returns a slice of container workload profiles from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetContainerWkldProfiles(queryParameters map[string]string, containerClusterID string) (api APIResponse, err error) {
	api, err = p.GetCollection("container_clusters/"+containerClusterID+"/container_workload_profiles", false, queryParameters, &p.ContainerWorkloadProfilesSlice)
	if len(p.ContainerWorkloadProfilesSlice) >= 500 {
		p.ContainerWorkloadProfilesSlice = nil
		api, err = p.GetCollection("container_clusters/"+containerClusterID+"/container_workload_profiles", true, queryParameters, &p.ContainerWorkloadProfilesSlice)
	}
	p.ContainerWorkloadProfiles = make(map[string]ContainerWorkloadProfile)
	for _, c := range p.ContainerWorkloadProfilesSlice {
		p.ContainerWorkloadProfiles[c.Href] = c
		if c.Name != nil {
			p.ContainerWorkloadProfiles[*c.Name] = c
		}
	}
	return api, err
}

// UpdateContainerWkldProfiles updates an existing container workload profile in the Illumio PCE
// The provided container workload profile struct must include an href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateContainerWkldProfiles(cp ContainerWorkloadProfile) (APIResponse, error) {
	cp.SanitizeContainerWorkloadProfilePut()
	api, err := p.Put(&cp)
	return api, err
}

// SanitizeContainerWorkloadProfilePut removes fields not acceptable to the put method.
func (c *ContainerWorkloadProfile) SanitizeContainerWorkloadProfilePut() {
	c.CreatedAt = ""
	c.CreatedBy = nil
	c.Linked = nil
	c.UpdatedAt = ""
	c.UpdatedBy = nil
	c.Namespace = ""

	// Make sure labels are just hrefs
	newLabels := []Label{}
	for _, l := range *c.Labels {
		var newLabel Label
		if l.Assignment.Href != "" {
			newLabel = Label{Assignment: &Assignment{Href: l.Assignment.Href}, Key: l.Key}
		} else {
			newRestrictions := []Restriction{}
			for _, r := range PtrToVal(l.Restriction) {
				newRestrictions = append(newRestrictions, Restriction{Href: r.Href})
			}
			newLabel = Label{Key: l.Key, Restriction: &newRestrictions}
		}
		newLabels = append(newLabels, newLabel)
	}
	c.Labels = &newLabels

}

// GetLabelByKey returns the value for a provided label key
func (c *ContainerWorkloadProfile) GetLabelByKey(key string) string {
	for _, l := range PtrToVal(c.Labels) {
		// Skip if it's not the key specified
		if l.Key != key {
			continue
		}
		if len(PtrToVal(l.Restriction)) > 0 {
			return ""
		}
		return l.Assignment.Value
	}
	return ""
}

// SetLabelByKey sets the specified label
func (c *ContainerWorkloadProfile) SetLabel(label Label, pce *PCE) error {
	// Confirm we have labels
	if len(pce.LabelsSlice) == 0 {
		return errors.New("pce is not loaded with labels")
	}

	// Create the new label array
	newLabels := []Label{}

	// Iterate through the existing labels
	for _, existingLabel := range PtrToVal(c.Labels) {
		// If the key isn't target, keep it
		if existingLabel.Key != label.Key {
			newLabels = append(newLabels, existingLabel)
		}
	}
	// Add the new label
	newLabels = append(newLabels, Label{Key: label.Key, Assignment: &Assignment{Href: label.Href, Value: label.Value}})

	// Update the labels
	c.Labels = &newLabels

	return nil
}

// SetLabelByKey sets the specified label
func (c *ContainerWorkloadProfile) RemoveLabel(key string) error {

	// Create the new label array
	newLabels := []Label{}

	// Iterate through the existing labels
	for _, existingLabel := range *c.Labels {
		// If the key isn't target, keep it
		if existingLabel.Key != key {
			newLabels = append(newLabels, existingLabel)
		}
	}

	// Update the labels
	c.Labels = &newLabels

	return nil
}
