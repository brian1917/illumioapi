package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Event represents an auditable event in the Illumio PCE
type Event struct {
	Href           string          `json:"href"`
	Timestamp      time.Time       `json:"timestamp"`
	PceFqdn        string          `json:"pce_fqdn"`
	EventCreatedBy EventCreatedBy  `json:"created_by"`
	EventType      string          `json:"event_type"`
	Status         string          `json:"status"`
	Severity       string          `json:"severity"`
	Notifications  []Notifications `json:"notifications"`
}

// EventCreatedBy is who created the event
type EventCreatedBy struct {
	Agent            Agent            `json:"agent"`
	User             UserLogin        `json:"user"`
	ContainerCluster ContainerCluster `json:"container_cluster"`
	System           System           `json:"system,omitempty"`
	Name             string
	Href             string
}

// System is an empty struct for system-generated events
type System struct {
}

// Notifications are event notifications
type Notifications struct {
	UUID             string `json:"uuid"`
	NotificationType string `json:"notification_type"`
	Info             Info   `json:"info"`
}

// Info are notification info
type Info struct {
	APIEndpoint string `json:"api_endpoint"`
	APIMethod   string `json:"api_method"`
	SrcIP       string `json:"src_ip"`
}

// GetAllEvents returns a slice of events in the Illumio PCE.
// The first API call to the PCE does not use the async option.
// If the array length is >=500, it re-runs with async.
// QueryParameters can be passed as a map of [key]=vale
func (p *PCE) GetAllEvents(queryParameters map[string]string) ([]Event, APIResponse, error) {
	var api APIResponse

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/events")
	if err != nil {
		return nil, api, fmt.Errorf("get all events - %s", err)
	}

	// Set the query parameters
	for key, value := range queryParameters {
		q := apiURL.Query()
		q.Set(key, value)
		apiURL.RawQuery = q.Encode()
	}

	// Call the API
	api, err = apicall("GET", apiURL.String(), *p, nil, false)
	if err != nil {
		return nil, api, fmt.Errorf("get all events - %s", err)
	}

	var events []Event
	json.Unmarshal([]byte(api.RespBody), &events)

	if len(events) < 500 {
		for i, e := range events {
			e.PopulateCreatedBy()
			events[i] = e
		}
		return events, api, nil
	}

	// If length is 500, re-run with async
	api, err = apicall("GET", apiURL.String(), *p, nil, true)
	if err != nil {
		return nil, api, fmt.Errorf("get all events - %s", err)
	}
	// Unmarshal response to asyncEvents and return
	var asyncEvents []Event
	json.Unmarshal([]byte(api.RespBody), &asyncEvents)

	for i, e := range asyncEvents {
		e.PopulateCreatedBy()
		asyncEvents[i] = e
	}
	return asyncEvents, api, nil

}

func (e *Event) PopulateCreatedBy() {
	if e.EventCreatedBy.Agent.Href != "" {
		e.EventCreatedBy.Href = e.EventCreatedBy.Agent.Href
		e.EventCreatedBy.Name = e.EventCreatedBy.Agent.Hostname
	} else if e.EventCreatedBy.User.Href != "" {
		e.EventCreatedBy.Href = e.EventCreatedBy.User.Href
		e.EventCreatedBy.Name = e.EventCreatedBy.User.Username
	} else if e.EventCreatedBy.ContainerCluster.Href != "" {
		e.EventCreatedBy.Href = e.EventCreatedBy.ContainerCluster.Href
		e.EventCreatedBy.Name = e.EventCreatedBy.ContainerCluster.Name
	} else {
		e.EventCreatedBy.Href = "system"
		e.EventCreatedBy.Name = "system"
	}
}
