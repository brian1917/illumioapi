package illumioapi_test

import (
	"testing"

	"stash.ilabs.io/scm/~brian.pitta/illumioapi.git"
)

func TestBoundServices(t *testing.T) {

	// Clear previous test runs in case one did not complete
	allBoundServices, api, _ := illumioapi.GetAllBoundServices(pce, "draft")
	for _, BoundService := range allBoundServices {
		if BoundService.Name == "go_test_BoundService" || BoundService.Name == "go_test_updated_BoundService" {
			illumioapi.DeleteHref(pce, BoundService.Href)
		}
	}

	// Create new BoundService
	newService, api, _ := illumioapi.CreateService(pce, illumioapi.Service{Name: "go_test_service", ServicePorts: []*illumioapi.ServicePort{&illumioapi.ServicePort{Port: 80, Protocol: 6}}})
	newBoundService, api, _ := illumioapi.CreateBoundService(pce, illumioapi.BoundService{Name: "go_test_BoundService", Service: &illumioapi.Service{Href: newService.Href}})
	if api.StatusCode != 201 {
		t.Errorf("CreateBoundService is returning a status code of %d", api.StatusCode)
		t.Errorf("CreateBoundService has an API Resp Body of: %s", api.RespBody)
	}

	// Get all draft BoundServices
	allBoundServices, api, _ = illumioapi.GetAllBoundServices(pce, "draft")
	if len(allBoundServices) < 1 {
		t.Errorf("GetAllBoundServices is not returning a populated array")
	}

	// Update a BoundService
	newBoundService.Name = "go_test_updated_BoundService"
	api, _ = illumioapi.UpdateBoundService(pce, newBoundService)
	if api.StatusCode != 204 {
		t.Errorf("UpdateBoundService is returning a status code of %d", api.StatusCode)
	}

	// Clear created objects
	allBoundServices, api, _ = illumioapi.GetAllBoundServices(pce, "draft")
	for _, BoundService := range allBoundServices {
		if BoundService.Name == "go_test_BoundService" || BoundService.Name == "go_test_updated_BoundService" {
			illumioapi.DeleteHref(pce, BoundService.Href)
		}
	}

	// Clear created service
	allServices, api, _ := illumioapi.GetAllServices(pce, "draft")
	for _, service := range allServices {
		if service.Name == "go_test_service" {
			illumioapi.DeleteHref(pce, service.Href)
		}
	}

}
