package illumioapi_test

import (
	"fmt"
	"testing"

	"stash.ilabs.io/scm/~brian.pitta/illumioapi.git"
)

func TestServices(t *testing.T) {

	// Clear previous test runs in case one did not complete
	allServices, api, _ := illumioapi.GetAllServices(pce, "draft")
	for _, service := range allServices {
		if service.Name == "go_test_service" || service.Name == "go_test_updated_service" {
			illumioapi.DeleteHref(pce, service.Href)
		}
	}

	// Create new service
	newService, api, _ := illumioapi.CreateService(pce, illumioapi.Service{Name: "go_test_service", ServicePorts: []*illumioapi.ServicePort{&illumioapi.ServicePort{Port: 80, Protocol: 6}}})
	if api.StatusCode != 201 {
		t.Errorf("CreateService is returning a status code of %d", api.StatusCode)
	}

	// Get all draft services
	allServices, api, _ = illumioapi.GetAllServices(pce, "draft")
	if len(allServices) < 1 {
		t.Errorf("GetAllServices is not returning a populated array")
	}

	// Update a label
	newService.Name = "go_test_updated_service"
	api, err := illumioapi.UpdateService(pce, newService)
	if err != nil {
		fmt.Println(api.RespBody)
	}
	if api.StatusCode != 204 {
		t.Errorf("UpdateService is returning a status code of %d", api.StatusCode)
	}

	// Clear created objects
	allServices, api, _ = illumioapi.GetAllServices(pce, "draft")
	for _, service := range allServices {
		if service.Name == "go_test_service" || service.Name == "go_test_updated_service" {
			illumioapi.DeleteHref(pce, service.Href)
		}
	}

}
