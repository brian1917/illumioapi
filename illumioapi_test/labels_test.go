package illumioapi_test

import (
	"log"
	"testing"

	"github.com/brian1917/illumioapi"
)

var pce illumioapi.PCE
var err error

func init() {
	pce, err = illumioapi.PCEbuilder("pce.lot48labs.com", "brian.pitta@illumio.com", "LocalIllumio1", 8443, true)
	if err != nil {
		log.Fatal("PCE Builder failed")
	}

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

	// Get a label by HREF
	getLabelbyHref, api, _ := illumioapi.GetLabelbyHref(pce, newLabel.Href)
	if api.StatusCode != 200 {
		t.Errorf("GetLabelbyHref is returning a status code of %d", api.StatusCode)
	}
	if getLabelbyHref.Value != newLabel.Value {
		t.Errorf("GetLabelbyHref did not find the right label. The value returned was %s", getLabelbyHref.Value)
	}

	// Get a specific label
	getLabel, api, _ := illumioapi.GetLabelbyKeyValue(pce, "role", "updated_test_role")
	if getLabel.Href != newLabel.Href {
		t.Errorf("GetLabelbyKeyValue is not finding the right updated label")
	}

	// Delete Created label
	deleteAPI, _ := illumioapi.DeleteHref(pce, newLabel.Href)
	if deleteAPI.StatusCode != 204 {
		t.Errorf("DeleteHref for the label is returning a status code of %d", deleteAPI.StatusCode)
	}

}
