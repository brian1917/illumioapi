package illumioapi

type LabelDimension struct {
	Href                  string              `json:"href"`
	Key                   string              `json:"key"`
	DisplayName           string              `json:"display_name"`
	CreatedAt             string              `json:"created_at"`
	UpdatedAt             string              `json:"updated_at"`
	Deleted               bool                `json:"deleted"`
	DeletedAt             string              `json:"deleted_at"`
	Usage                 LabelDimensionUsage `json:"usage"`
	Caps                  []string            `json:"caps"`
	ExternalDataSet       string              `json:"external_data_set,omitempty"`
	ExternalDataReference string              `json:"external_data_reference,omitempty"`
	CreatedBy             CreatedBy           `json:"created_by"`
	UpdatedBy             UpdatedBy           `json:"updated_by"`
	DeletedBy             DeletedBy           `json:"deleted_by"`
}

type LabelDimensionUsage struct {
	Labels      bool `json:"labels"`
	LabelGroups bool `json:"label_groups"`
}

// GetLabelDimensions returns a slice of label tpes from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetLabelDimensions(queryParameters map[string]string) (labelDimensions []LabelDimension, api APIResponse, err error) {
	api, err = p.GetCollection("label_dimensions", false, queryParameters, &labelDimensions)
	if len(labelDimensions) >= 500 {
		labelDimensions = nil
		api, err = p.GetCollection("labels", true, queryParameters, &labelDimensions)
	}
	return labelDimensions, api, err
}
