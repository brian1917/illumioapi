package illumioapi

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TrafficAnalysisRequest represents the payload object for the traffic analysis POST request
type TrafficAnalysisRequest struct {
	Sources         Sources      `json:"sources"`
	Destinations    Destinations `json:"destinations"`
	PortProtos      PortProtos   `json:"port_protos"`
	StartDate       time.Time    `json:"start_date,omitempty"`
	EndDate         time.Time    `json:"end_date,omitempty"`
	PolicyDecisions []string     `json:"policy_decisions"`
	MaxResults      int          `json:"max_results,omitempty"`
}

// Sources represents the sources query portion of the explorer API
type Sources struct {
	Include [][]Include `json:"include"`
	Exclude []Exclude   `json:"exclude"`
}

//Destinations represents the destination query portion of the explorer API
type Destinations struct {
	Include [][]Include `json:"include"`
	Exclude []Exclude   `json:"exclude"`
}

// PortProtos represents the ports and protocols query portion of the exporer API
type PortProtos struct {
	Include []Include `json:"include"`
	Exclude []Exclude `json:"exclude"`
}

// Include represents the type of objects used in an include query.
//
// The include struct should only have the following combinations: label only, workload only, IP address only, Port and/or protocol only.
//
// Example - Label and Workload cannot both be non-nil
//
// Example - Port and Proto can both be non-nil (e.g., port 3306 and proto 6)
type Include struct {
	Label     *Label     `json:"label,omitempty"`
	Workload  *Workload  `json:"workload,omitempty"`
	IPAddress *IPAddress `json:"ip_address,omitempty"`
	Port      int        `json:"port,omitempty"`
	Proto     int        `json:"proto,omitempty"`
}

// Exclude represents the type of objects used in an include query.
//
// The exclude struct should only have the following combinations: label only, workload only, IP address only, Port and/or protocol only.
//
// Example - Label and Workload cannot both be non-nil
//
// Example - Port and Proto can both be non-nil (e.g., port 3306 and proto 6)
type Exclude struct {
	Label     *Label     `json:"label,omitempty"`
	Workload  *Workload  `json:"workload,omitempty"`
	IPAddress *IPAddress `json:"ip_address,omitempty"`
	Port      int        `json:"port,omitempty"`
	Proto     int        `json:"proto,omitempty"`
}

// IPAddress represents an IP Address used in a query
type IPAddress struct {
	Value string `json:"value,omitempty"`
}

//TrafficAnalysis represents the response from the traffic analysis api
type TrafficAnalysis struct {
	Dst            *Dst            `json:"dst"`
	NumConnections int             `json:"num_connections"`
	PolicyDecision string          `json:"policy_decision"`
	Port           int             `json:"port"`
	Proto          int             `json:"proto"`
	Src            *Src            `json:"src"`
	TimestampRange *TimestampRange `json:"timestamp_range"`
}

// Dst Traffic flow endpoint details
type Dst struct {
	IP       string    `json:"ip"`
	Workload *Workload `json:"workload,omitempty"`
}

// Src Traffic flow endpoint details
type Src struct {
	IP       string    `json:"ip"`
	Workload *Workload `json:"workload,omitempty"`
}

// TimestampRange Timestamp ranges for the flow detected
type TimestampRange struct {
	FirstDetected string `json:"first_detected"`
	LastDetected  string `json:"last_detected"`
}

// GetTrafficAnalysis gets flow data from Explorer.
//
// sourcesInclude, sourcesExclude, destinationsInclude, destinationsExclude are array of strings that are hrefs for labels, hrefs for workloads, or values for ip_addresses.
//
// portProtoInclude and portProtoExclude are an array of arrays. For example, [[3306, 6], [8080,-1]] is Port 3306 TCP and Port 8080 any protocol.
//
// policyStatuses is an array that contains only the values allowed, potentially_blocked, and/or blocked.
func GetTrafficAnalysis(pce PCE, sourcesInclude, sourcesExclude, destinationsInclude, destinationsExclude []string, portProtoInclude,
	portProtoExclude [][2]int, startTime, endTime time.Time, policyStatuses []string, maxFLows int) ([]TrafficAnalysis, error) {

	// Initialize arrays using "make" so JSON is marshaled with empty arrays and not null values to meet Illumio API spec
	sourceInc := make([]Include, 0)
	destInc := make([]Include, 0)
	sourceExcl := make([]Exclude, 0)
	destExcl := make([]Exclude, 0)

	// Process source include, destination include, source exclude, and destination exclude
	queryLists := [][]string{sourcesInclude, destinationsInclude, sourcesExclude, destinationsExclude}

	// Start counter
	i := 0

	// For each list there are 4 possibilities: empty, label, workload, ipaddress
	for _, queryList := range queryLists {

		// Labels
		if strings.ContainsAny("label", queryList[0]) == true {
			for _, label := range queryLists[i] {
				queryLabel := Label{Href: label}
				switch i {
				case 0:
					sourceInc = append(sourceInc, Include{Label: &queryLabel})
				case 1:
					destInc = append(destInc, Include{Label: &queryLabel})
				case 2:
					sourceExcl = append(sourceExcl, Exclude{Label: &queryLabel})
				case 3:
					destExcl = append(destExcl, Exclude{Label: &queryLabel})
				}

			}

			// Workloads
		} else if strings.ContainsAny("workload", queryList[0]) == true {
			for _, workload := range queryLists[i] {
				queryWorkload := Workload{Href: workload}
				switch i {
				case 0:
					sourceInc = append(sourceInc, Include{Workload: &queryWorkload})
				case 1:
					destInc = append(destInc, Include{Workload: &queryWorkload})
				case 2:
					sourceExcl = append(sourceExcl, Exclude{Workload: &queryWorkload})
				case 3:
					destExcl = append(destExcl, Exclude{Workload: &queryWorkload})
				}

			}

			// Assume all else are IP addresses (API will error when needed)
		} else if len(queryList[0]) > 0 {
			for _, ipAddress := range queryLists[i] {
				queryIPAddress := IPAddress{Value: ipAddress}
				switch i {
				case 0:
					sourceInc = append(sourceInc, Include{IPAddress: &queryIPAddress})
				case 1:
					destInc = append(destInc, Include{IPAddress: &queryIPAddress})
				case 2:
					sourceExcl = append(sourceExcl, Exclude{IPAddress: &queryIPAddress})
				case 3:
					destExcl = append(destExcl, Exclude{IPAddress: &queryIPAddress})
				}
			}
		}

		i++
	}

	// Process info for Port and protocol include
	portProtoInc := make([]Include, 0)
	if len(portProtoInclude) > 0 {
		for _, portProto := range portProtoInclude {
			portProtoInc = append(portProtoInc, Include{Port: portProto[0], Proto: portProto[1]})
		}
	}

	// Process info for Port and protocol exclude
	portProtoExcl := make([]Exclude, 0)
	if len(portProtoExclude) > 0 {
		for _, portProto := range portProtoExclude {
			portProtoExcl = append(portProtoExcl, Exclude{Port: portProto[0], Proto: portProto[1]})
		}
	}

	// Build the TrafficAnalysisRequest struct
	traffic := TrafficAnalysisRequest{
		Sources: Sources{
			Include: [][]Include{sourceInc},
			Exclude: sourceExcl},
		Destinations: Destinations{
			Include: [][]Include{destInc},
			Exclude: destExcl},
		PortProtos: PortProtos{
			Include: portProtoInc,
			Exclude: portProtoExcl},
		PolicyDecisions: policyStatuses,
		StartDate:       startTime,
		EndDate:         endTime,
		MaxResults:      maxFLows}

	// Create JSON Payload
	jsonPayload, err := json.Marshal(traffic)
	if err != nil {
		return nil, fmt.Errorf("get traffic analysis - %s", err)
	}

	var trafficResponses []TrafficAnalysis

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(pce.FQDN) + ":" + strconv.Itoa(pce.Port) + "/api/v1/orgs/" + strconv.Itoa(pce.Org) + "/traffic_flows/traffic_analysis_queries")
	if err != nil {
		return nil, fmt.Errorf("get traffic analysis - %s", err)
	}

	// Call the API
	api, err := apicall("POST", apiURL.String(), pce, jsonPayload, false)
	if err != nil {
		return nil, fmt.Errorf("get traffic analysis - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &trafficResponses)

	return trafficResponses, nil

}
