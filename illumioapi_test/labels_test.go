package illumioapi_test

import (
	"testing"

	"stash.ilabs.io/scm/~brian.pitta/illumioapi.git"
)

var pce illumioapi.PCE

func init() {
	pce.FQDN = "demo4.illum.io"
	pce.Port = 443
	pce.Org = 14
	pce.User = "api_1832dadcb7683e31e"
	pce.Key = "40f81671df413cf100d892fa044a0d3ee6dfb62a2514ab4684d985709edc6fcf"
	pce.DisableTLSChecking = false
}

func TestLabels(t *testing.T) {

	// Clear previous test runs
	checkExisting1, api, _ := illumioapi.GetLabel(pce, "role", "test_role")
	if checkExisting1.Href != "" {
		illumioapi.DeleteHref(pce, checkExisting1.Href)
	}
	checkExisting2, api, _ := illumioapi.GetLabel(pce, "role", "updated_test_role")
	if checkExisting2.Href != "" {
		illumioapi.DeleteHref(pce, checkExisting2.Href)
	}

	// Create new label
	newLabel, api, _ := illumioapi.CreateLabel(pce, illumioapi.Label{Key: "role", Value: "test_role"})
	if api.StatusCode != 201 {
		t.Errorf("CreateLabel is returning a status code of %d", api.StatusCode)
	}

	// Get all labels
	allLabels, api, _ := illumioapi.GetAllLabels(pce)
	if len(allLabels) < 1 {
		t.Errorf("GetAllLabels is not returning a populated array")
	}

	// Update a label
	newLabel.Value = "updated_test_role"
	api, _ = illumioapi.UpdateLabel(pce, newLabel)
	if api.StatusCode != 204 {
		t.Errorf("UpdateLabel is returning a status code of %d", api.StatusCode)
	}

	// Get a specific label
	getLabel, api, _ := illumioapi.GetLabel(pce, "role", "updated_test_role")
	if getLabel.Href != newLabel.Href {
		t.Errorf("GetLabel is not finding the right updated label")
	}

	// Delete Created label
	deleteAPI, _ := illumioapi.DeleteHref(pce, newLabel.Href)
	if deleteAPI.StatusCode != 204 {
		t.Errorf("DeleteHref for the label is returning a status code of %d", deleteAPI.StatusCode)
	}

}
