package illumioapi

// Deprecated: use GetLabels instead
func (p *PCE) GetAllLabels() ([]Label, APIResponse, error) {
	l, a, err := p.GetLabels(nil)
	return l, a, err
}

// Deprecated: use GetLabelByKeyValue instead
func (p *PCE) GetLabelbyKeyValue(key, value string) (Label, APIResponse, error) {
	l, a, err := p.GetLabelByKeyValue(key, value)
	return l, a, err
}

// Deprecated: use GetLabelByHref instead.
func (p *PCE) GetLabelbyHref(href string) (Label, APIResponse, error) {
	l, a, err := p.GetLabelByHref(href)
	return l, a, err
}
