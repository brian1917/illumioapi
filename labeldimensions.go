package illumioapi

type LabelDimension struct {
	Href                  string               `json:"href,omitempty"`
	Key                   string               `json:"key,omitempty"`
	DisplayName           string               `json:"display_name,omitempty"`
	DisplayInfo           *DisplayInfo         `json:"display_info,omitempty"`
	Usage                 *LabelDimensionUsage `json:"usage,omitempty"`
	Caps                  *[]string            `json:"caps,omitempty"`
	ExternalDataSet       *string              `json:"external_data_set,omitempty"`
	ExternalDataReference *string              `json:"external_data_reference,omitempty"`
	Deleted               *bool                `json:"deleted,omitempty"`
	CreatedAt             string               `json:"created_at,omitempty"`
	CreatedBy             *Href                `json:"created_by,omitempty"`
	UpdatedAt             string               `json:"updated_at,omitempty"`
	UpdatedBy             *Href                `json:"updated_by,omitempty"`
	DeletedAt             string               `json:"deleted_at,omitempty"`
	DeletedBy             *Href                `json:"deleted_by,omitempty"`
}

type DisplayInfo struct {
	BackgroundColor   string `json:"background_color,omitempty"`
	Icon              string `json:"icon,omitempty"`
	ForegroundColor   string `json:"foreground_color,omitempty"`
	Initial           string `json:"initial,omitempty"`
	DisplayNamePlural string `json:"display_name_plural,omitempty"`
}

type LabelDimensionUsage struct {
	Labels      bool `json:"labels"`
	LabelGroups bool `json:"label_groups"`
}

// GetLabelDimensions returns a slice of label tpes from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetLabelDimensions(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("label_dimensions", false, queryParameters, &p.LabelDimensionsSlice)
	if len(p.LabelDimensionsSlice) >= 500 {
		p.LabelDimensionsSlice = nil
		api, err = p.GetCollection("label_dimensions", true, queryParameters, &p.LabelDimensionsSlice)
	}
	p.LabelDimensions = make(map[string]LabelDimension)
	for _, ld := range p.LabelDimensionsSlice {
		p.LabelDimensions[ld.Href] = ld
		p.LabelDimensions[ld.Key] = ld
	}
	return api, err
}

// CreateLabelDimensions creates a new label dimension in the PCE.
func (p *PCE) CreateLabelDimension(labelDimension LabelDimension) (createdLabelDimension LabelDimension, api APIResponse, err error) {
	api, err = p.Post("label_dimensions", &labelDimension, &createdLabelDimension)
	return createdLabelDimension, api, err
}

// UpdateLabelDimension updates an existing label dimension in the PCE.
// The provided label dimension must include an Href.
// Properties that cannot be included in the PUT method will be ignored.
func (p *PCE) UpdateLabelDimension(labelDimension LabelDimension) (APIResponse, error) {
	labelDimension.Usage = nil
	labelDimension.Key = ""
	labelDimension.CreatedAt = ""
	labelDimension.CreatedBy = nil
	labelDimension.UpdatedAt = ""
	labelDimension.UpdatedBy = nil
	labelDimension.DeletedAt = ""
	labelDimension.DeletedBy = nil
	labelDimension.Caps = nil
	labelDimension.Deleted = nil

	api, err := p.Put(&labelDimension)
	return api, err
}
