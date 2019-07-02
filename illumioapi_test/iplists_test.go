package illumioapi_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/brian1917/illumioapi"
)

func TestIPLists(t *testing.T) {

	// Clear previous test runs in case one did not complete
	allIPLists, api, _ := illumioapi.GetAllIPLists(pce, "draft")
	for _, ipList := range allIPLists {
		if strings.Contains(ipList.Name, "go_test_iplist") {
			illumioapi.DeleteHref(pce, ipList.Href)
		}
	}

	// Create new ipList
	i := []illumioapi.IPList{
		illumioapi.IPList{Name: "go_test_iplist1", IPRanges: []*illumioapi.IPRange{&illumioapi.IPRange{FromIP: "192.168.0.0"}}},
		illumioapi.IPList{Name: "go_test_iplist2", IPRanges: []*illumioapi.IPRange{&illumioapi.IPRange{FromIP: "192.168.0.0/16"}}},
		illumioapi.IPList{Name: "go_test_iplist3", IPRanges: []*illumioapi.IPRange{&illumioapi.IPRange{FromIP: "0.0.0.0/0"}, &illumioapi.IPRange{FromIP: "10.0.0.0/8", Exclusion: true}}}}

	for _, ipList := range i {
		newIPList, api, _ := illumioapi.CreateIPList(pce, ipList)
		if api.StatusCode != 201 {
			t.Errorf("CreateIPList is returning a status code of %d", api.StatusCode)
		}
	}

	// Get all IPLists
	allIPLists, api, _ = illumioapi.GetAllIPLists(pce)
	count := 0
	for _, ipList := range allIPLists {
		if strings.Contains(ipList.Name, "go_test_iplist"){
			count ++
		}}
		if count != 3 {
			t.Errorf("GetAllIPLists is not 3 test IPLists")
		}
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
