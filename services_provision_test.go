package illumioapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestServiceProvisionHrefOnly guards against a regression where Service.Name
// (tagged `json:"name"` without omitempty) forced an empty "name":"" into the
// provision change_subset. The PCE's POST /sec_policy rejected that with a 406
// invalid_uri / not_acceptable error, so `delete --provision` of services never
// committed and objects piled up in a pending-delete draft. A provision
// reference must serialize href-only: {"href":"..."}.
func TestServiceProvisionHrefOnly(t *testing.T) {
	href := "/orgs/1/sec_policy/draft/services/123"
	b, err := json.Marshal(&Service{Href: href})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	got := string(b)
	if strings.Contains(got, "\"name\"") {
		t.Errorf("Service provision reference must not emit a name field; got %s", got)
	}
	if got != `{"href":"`+href+`"}` {
		t.Errorf("expected href-only object, got %s", got)
	}
}

// TestServiceNameOmittedWhenEmpty is the narrow unit form of the same fix.
func TestServiceNameOmittedWhenEmpty(t *testing.T) {
	b, _ := json.Marshal(&Service{Href: "/orgs/1/services/9"})
	if strings.Contains(string(b), "name") {
		t.Errorf("empty Name should be omitted; got %s", string(b))
	}
	// A populated name must still serialize (normal create/update path).
	b2, _ := json.Marshal(&Service{Name: "telnet"})
	if !strings.Contains(string(b2), `"name":"telnet"`) {
		t.Errorf("non-empty Name must serialize; got %s", string(b2))
	}
}
