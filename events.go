package illumioapi

import (
	"time"
)

// Event represents an auditable event in the Illumio PCE
// Events cannot be created or updated.
type Event struct {
	Href            string             `json:"href"`
	Timestamp       time.Time          `json:"timestamp"`
	PceFqdn         string             `json:"pce_fqdn"`
	EventCreatedBy  *EventCreatedBy    `json:"created_by"`
	EventType       string             `json:"event_type"`
	Status          string             `json:"status"`
	Severity        string             `json:"severity"`
	Notifications   *[]Notifications   `json:"notifications"`
	ResourceChanges *[]ResourceChanges `json:"resource_changes,omitempty"`
}

// EventCreatedBy is who created the event
type EventCreatedBy struct {
	Agent            *Agent           `json:"agent"`
	VEN              *VEN             `json:"ven"` // VEN is optional, used for events created by VENs
	User             UserLogin        `json:"user"`
	ContainerCluster ContainerCluster `json:"container_cluster"`
	System           System           `json:"system,omitempty"`
	Name             string
	Href             string
}

// System is an empty struct for system-generated events
type System struct{}

// Notifications are event notifications
type Notifications struct {
	UUID             string `json:"uuid"`
	NotificationType string `json:"notification_type"`
	Info             *Info  `json:"info"`
}

// Info are notification info
type Info struct {
	APIEndpoint string `json:"api_endpoint"`
	APIMethod   string `json:"api_method"`
	SrcIP       string `json:"src_ip"`
	VEN         *VEN   `json:"ven,omitempty"`
	Agent       *Agent `json:"agent,omitempty"`
}

type ResourceChanges struct {
	UUID       string   `json:"uuid,omitempty"`
	Resource   Resource `json:"resource,omitempty"`
	ChangeType string   `json:"change_type,omitempty"`
}

type Resource struct {
	Workload *Workload `json:"workload,omitempty"`
	VEN      *VEN      `json:"ven,omitempty"`
	Agent    *Agent    `json:"agent,omitempty"`
}

// GetEvents returns a slice of events from the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetEvents(queryParameters map[string]string) (events []Event, api APIResponse, err error) {
	api, err = p.GetCollection("events", false, queryParameters, &events)
	if len(events) >= 500 {
		events = nil
		api, err = p.GetCollection("events", true, queryParameters, &events)
	}
	for i, e := range events {
		e.PopulateCreatedBy()
		events[i] = e
	}
	return events, api, err
}

func (e *Event) PopulateCreatedBy() {
	if e.EventCreatedBy == nil {
		e.EventCreatedBy = &EventCreatedBy{}
	}
	cb := e.EventCreatedBy
	if cb.VEN != nil && cb.VEN.Href != "" {
		cb.Href = cb.VEN.Href
		cb.Name = PtrToVal(cb.VEN.Hostname)
	} else if cb.Agent != nil && cb.Agent.Href != "" {
		cb.Href = cb.Agent.Href
		cb.Name = cb.Agent.Hostname
	} else if cb.User.Href != "" {
		cb.Href = cb.User.Href
		cb.Name = cb.User.Username
	} else if cb.ContainerCluster.Href != "" {
		cb.Href = cb.ContainerCluster.Href
		cb.Name = cb.ContainerCluster.Name
	} else {
		cb.Href = "system"
		cb.Name = "system"
	}
}
