package illumioapi_test

import (
	"fmt"
	"testing"

	"github.com/brian1917/illumioapi"
)

func TestIPLists(t *testing.T) {

	// Clear previous test runs in case one did not complete
	allIPLists, api, _ := illumioapi.GetAllIPLists(pce, "draft")
	for _, ipList := range allIPLists {
		if ipList.Name == "go_test_iplist" || ipList.Name == "go_test_updated_iplist" {
			illumioapi.DeleteHref(pce, ipList.Href)
		}
	}

	// Create new ipList
	newIPList, api, _ := illumioapi.CreateIPList(pce, illumioapi.IPList{Name: "go_test_iplist", IPRanges: []*illumioapi.IPRange{&illumioapi.IPRange{FromIP: "192.168.2.20"}}})
	if api.StatusCode != 201 {
		t.Errorf("CreateIPList is returning a status code of %d", api.StatusCode)
	}

	// Get all draft iplists
	allIPLists, api, _ = illumioapi.GetAllIPLists(pce, "draft")
	if len(allIPLists) < 1 {
		t.Errorf("GetAllIPLists is not returning a populated array")
	}

	// Update an IPList
	newIPList.Name = "go_test_updated_iplist"
	api, err := illumioapi.UpdateIPList(pce, newIPList)
	if err != nil {
		fmt.Println(api.RespBody)
	}
	if api.StatusCode != 204 {
		t.Errorf("UpdateIPList is returning a status code of %d", api.StatusCode)
	}

	// Clear created objects
	allIPLists, api, _ = illumioapi.GetAllIPLists(pce, "draft")
	for _, ipList := range allIPLists {
		if ipList.Name == "go_test_iplist" || ipList.Name == "go_test_updated_iplist" {
			illumioapi.DeleteHref(pce, ipList.Href)
		}
	}

}
