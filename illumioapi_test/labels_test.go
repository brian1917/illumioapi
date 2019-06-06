package illumioapi_test

import (
	"testing"

	"github.com/brian1917/illumioapi"
)

var pce illumioapi.PCE

func init() {
	pce.FQDN = "pce-snc.illumioeval.com"
	pce.Port = 8443
	pce.Org = 1
	pce.User = "<api_user>"
	pce.Key = "<api_key>"
	pce.DisableTLSChecking = false
}

func TestLabels(t *testing.T) {

	// Clear previous test runs
	checkExisting1, api, _ := illumioapi.GetLabelbyKeyValue(pce, "role", "test_role")
	if checkExisting1.Href != "" {
		illumioapi.DeleteHref(pce, checkExisting1.Href)
	}
	checkExisting2, api, _ := illumioapi.GetLabelbyKeyValue(pce, "role", "updated_test_role")
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
	getLabel, api, _ := illumioapi.GetLabelbyKeyValue(pce, "role", "updated_test_role")
	if getLabel.Href != newLabel.Href {
		t.Errorf("GetLabel is not finding the right updated label")
	}

	// Delete Created label
	deleteAPI, _ := illumioapi.DeleteHref(pce, newLabel.Href)
	if deleteAPI.StatusCode != 204 {
		t.Errorf("DeleteHref for the label is returning a status code of %d", deleteAPI.StatusCode)
	}

}
