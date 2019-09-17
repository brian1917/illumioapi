package illumioapi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TrafficAnalysisRequest represents the payload object for the traffic analysis POST request
type TrafficAnalysisRequest struct {
	Sources          Sources          `json:"sources"`
	Destinations     Destinations     `json:"destinations"`
	ExplorerServices ExplorerServices `json:"services"`
	StartDate        time.Time        `json:"start_date,omitempty"`
	EndDate          time.Time        `json:"end_date,omitempty"`
	PolicyDecisions  []string         `json:"policy_decisions"`
	MaxResults       int              `json:"max_results,omitempty"`
}

// Sources represents the sources query portion of the explorer API
type Sources struct {
	Include [][]Include `json:"include"`
	Exclude []Exclude   `json:"exclude"`
}

// ExplorerServices represent services to be included or excluded in the explorer query
type ExplorerServices struct {
	Include []Include `json:"include"`
	Exclude []Exclude `json:"exclude"`
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
// The include struct should be label only, workload only, IP address only, Port and/or protocol only.
// Example - Label and Workload cannot both be non-nil
// Example - Port and Proto can both be non-nil (e.g., port 3306 and proto 6)
type Include struct {
	Label          *Label     `json:"label,omitempty"`
	Workload       *Workload  `json:"workload,omitempty"`
	IPAddress      *IPAddress `json:"ip_address,omitempty"`
	Port           int        `json:"port,omitempty"`
	ToPort         int        `json:"to_port,omitempty"`
	Proto          int        `json:"proto,omitempty"`
	Process        string     `json:"process_name,omitempty"`
	WindowsService string     `json:"windows_service_name,omitempty"`
}

// Exclude represents the type of objects used in an include query.
// The exclude struct should only have the following combinations: label only, workload only, IP address only, Port and/or protocol only.
// Example - Label and Workload cannot both be non-nil
// Example - Port and Proto can both be non-nil (e.g., port 3306 and proto 6)
type Exclude struct {
	Label          *Label     `json:"label,omitempty"`
	Workload       *Workload  `json:"workload,omitempty"`
	IPAddress      *IPAddress `json:"ip_address,omitempty"`
	Port           int        `json:"port,omitempty"`
	ToPort         int        `json:"to_port,omitempty"`
	Proto          int        `json:"proto,omitempty"`
	Process        string     `json:"process_name,omitempty"`
	WindowsService string     `json:"windows_service_name,omitempty"`
}

// IPAddress represents an IP Address
type IPAddress struct {
	Value string `json:"value,omitempty"`
}

// TrafficAnalysis represents the response from the explorer API
type TrafficAnalysis struct {
	Dst            *Dst            `json:"dst"`
	NumConnections int             `json:"num_connections"`
	PolicyDecision string          `json:"policy_decision"`
	ExpSrv         *ExpSrv         `json:"service"`
	Src            *Src            `json:"src"`
	TimestampRange *TimestampRange `json:"timestamp_range"`
}

// ExpSrv is a service in the explorer response
type ExpSrv struct {
	Port           int    `json:"port,omitempty"`
	Proto          int    `json:"proto,omitempty"`
	Process        string `json:"process_name,omitempty"`
	WindowsService string `json:"windows_service_name,omitempty"`
}

// Dst is the provider workload details
type Dst struct {
	IP       string    `json:"ip"`
	Workload *Workload `json:"workload,omitempty"`
}

// Src is the consumer workload details
type Src struct {
	IP       string    `json:"ip"`
	Workload *Workload `json:"workload,omitempty"`
}

// TimestampRange is used to limit queries ranges for the flow detected
type TimestampRange struct {
	FirstDetected string `json:"first_detected"`
	LastDetected  string `json:"last_detected"`
}

// TrafficQuery is the struct to be passed to the GetTrafficAnalysis function
type TrafficQuery struct {
	SourcesInclude        []string
	SourcesExclude        []string
	DestinationsInclude   []string
	DestinationsExclude   []string
	PortProtoInclude      [][2]int
	PortProtoExclude      [][2]int
	PortRangeInclude      [][2]int
	PortRangeExclude      [][2]int
	ProcessInclude        []string
	WindowsServiceInclude []string
	ProcessExclude        []string
	WindowsServiceExclude []string
	StartTime             time.Time
	EndTime               time.Time
	PolicyStatuses        []string
	MaxFLows              int
}

// FlowUploadResp is the response from the traffic upload API
type FlowUploadResp struct {
	NumFlowsReceived int       `json:"num_flows_received"`
	NumFlowsFailed   int       `json:"num_flows_failed"`
	FailedFlows      []*string `json:"failed_flows,omitempty"`
}

// GetTrafficAnalysis gets flow data from Explorer.
func (p *PCE) GetTrafficAnalysis(query TrafficQuery) ([]TrafficAnalysis, APIResponse, error) {
	var api APIResponse

	// Initialize arrays using "make" so JSON is marshaled with empty arrays and not null values to meet Illumio API spec
	sourceInc := make([]Include, 0)
	destInc := make([]Include, 0)

	sourceExcl := make([]Exclude, 0)
	destExcl := make([]Exclude, 0)

	// Process source include, destination include, source exclude, and destination exclude
	queryLists := [][]string{query.SourcesInclude, query.DestinationsInclude, query.SourcesExclude, query.DestinationsExclude}

	// Start counter
	i := 0

	// For each list there are 4 possibilities: empty, label, workload, ipaddress
	for _, queryList := range queryLists {

		// Labels
		if len(queryList) > 0 {
			if strings.Contains(queryList[0], "label") == true {
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
			} else if strings.Contains(queryList[0], "workload") == true {
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
		}

		i++
	}

	// Get the service data ready
	serviceInclude := make([]Include, 0)
	serviceExclude := make([]Exclude, 0)

	// Port and protocol - include
	for _, portProto := range query.PortProtoInclude {
		serviceInclude = append(serviceInclude, Include{Port: portProto[0], Proto: portProto[1]})
	}

	// Port and protocol - exclude
	for _, portProto := range query.PortProtoExclude {
		serviceExclude = append(serviceExclude, Exclude{Port: portProto[0], Proto: portProto[1]})
	}

	// Port Range - include
	for _, portRange := range query.PortRangeInclude {
		serviceInclude = append(serviceInclude, Include{Port: portRange[0], ToPort: portRange[1]})
	}

	// Port Range - exclude
	for _, portRange := range query.PortRangeExclude {
		serviceExclude = append(serviceExclude, Exclude{Port: portRange[0], ToPort: portRange[1]})
	}

	// Process - include
	for _, process := range query.ProcessInclude {
		serviceInclude = append(serviceInclude, Include{Process: process})
	}

	// Process - exclude
	for _, process := range query.ProcessExclude {
		serviceExclude = append(serviceExclude, Exclude{Process: process})
	}

	// Windows Service - include
	for _, winSrv := range query.WindowsServiceInclude {
		serviceInclude = append(serviceInclude, Include{WindowsService: winSrv})
	}

	// Windows Service - exclude
	for _, winSrv := range query.WindowsServiceExclude {
		serviceExclude = append(serviceExclude, Exclude{WindowsService: winSrv})
	}

	// Build the TrafficAnalysisRequest struct
	traffic := TrafficAnalysisRequest{
		Sources: Sources{
			Include: [][]Include{sourceInc},
			Exclude: sourceExcl},
		Destinations: Destinations{
			Include: [][]Include{destInc},
			Exclude: destExcl},
		ExplorerServices: ExplorerServices{
			Include: serviceInclude,
			Exclude: serviceExclude},
		PolicyDecisions: query.PolicyStatuses,
		StartDate:       query.StartTime,
		EndDate:         query.EndTime,
		MaxResults:      query.MaxFLows}

	// Create JSON Payload
	jsonPayload, err := json.Marshal(traffic)
	if err != nil {
		return nil, api, fmt.Errorf("get traffic analysis - %s", err)
	}

	var trafficResponses []TrafficAnalysis

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/traffic_flows/traffic_analysis_queries")
	if err != nil {
		return nil, api, fmt.Errorf("get traffic analysis - %s", err)
	}

	// Call the API
	api, err = apicall("POST", apiURL.String(), *p, jsonPayload, false)
	if err != nil {
		return nil, api, fmt.Errorf("get traffic analysis - %s", err)
	}

	// Unmarshal response to struct
	json.Unmarshal([]byte(api.RespBody), &trafficResponses)

	return trafficResponses, api, nil

}

//IterateTrafficJString iterates over each workload in a PCE to get all traffic data
func (p *PCE) IterateTrafficJString(stdout bool) (string, error) {

	// Threshold to query deeper
	threshold := 727

	// Get all explorer data to see where we are starting
	tq := TrafficQuery{
		StartTime:      time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC),
		EndTime:        time.Date(2020, 12, 30, 0, 0, 0, 0, time.UTC),
		PolicyStatuses: []string{"allowed", "potentially_blocked", "blocked"},
		MaxFLows:       100000}
	t, a, _ := p.GetTrafficAnalysis(tq)
	if stdout {
		fmt.Printf("Initial traffic query: %d records\r\n", len(t))
	}

	// If the length is under threshold return it and be done
	if len(t) < threshold {
		if stdout {
			fmt.Println("Done")
		}
		return a.RespBody, nil
	}

	if stdout {
		fmt.Println("Traffic records close to limit - querying by protocol...")
	}

	// If we are over threshold, run the query again for TCP, UDP, and everything else.
	// TCP
	tq.PortProtoInclude = [][2]int{[2]int{0, 6}}
	tcpT, tcpA, err := p.GetTrafficAnalysis(tq)
	if err != nil {
		return "", err
	}
	if stdout {
		fmt.Printf("TCP traffic query: %d records\r\n", len(tcpT))
	}
	// UDP
	tq.PortProtoInclude = [][2]int{[2]int{0, 17}}
	udpT, udpA, err := p.GetTrafficAnalysis(tq)
	if err != nil {
		return "", err
	}
	if stdout {
		fmt.Printf("UDP traffic query: %d records\r\n", len(udpT))
	}
	// Other Protos
	tq.PortProtoInclude = nil
	tq.PortProtoExclude = [][2]int{[2]int{0, 6}, [2]int{0, 17}}
	otherProtoT, otherProtoA, err := p.GetTrafficAnalysis(tq)
	if err != nil {
		return "", err
	}
	if stdout {
		fmt.Printf("Other traffic query: %d records\r\n", len(otherProtoT))
	}

	// Create a variable to hold final JSON strings and start with other protocols
	finalJSONSet := []string{otherProtoA.RespBody}

	// Process if TCP is over threshold
	if len(tcpT) > threshold {
		if stdout {
			fmt.Printf("TCP entries close to threshold (%d), querying by TCP port...\r\n", threshold)
		}
		tq.PortProtoInclude = [][2]int{[2]int{0, 6}}
		tq.PortProtoExclude = nil
		s, err := iterateOverPorts(*p, tq, tcpT, stdout)
		if err != nil {
			return "", err
		}
		finalJSONSet = append(finalJSONSet, s)
	} else {
		finalJSONSet = append(finalJSONSet, tcpA.RespBody)
	}

	// Process if UDP is over threshold
	if len(udpT) > threshold {
		if stdout {
			fmt.Printf("UDP entries close to threshold (%d), querying by UDP port...\r\n", threshold)
		}
		tq.PortProtoInclude = [][2]int{[2]int{0, 17}}
		tq.PortProtoExclude = nil
		s, err := iterateOverPorts(*p, tq, udpT, stdout)
		if err != nil {
			return "", err
		}
		finalJSONSet = append(finalJSONSet, s)
	} else {
		finalJSONSet = append(finalJSONSet, udpA.RespBody)
	}

	// Marshall the final set to get a count
	var FinalSet []TrafficAnalysis
	s := combineTrafficBodies(finalJSONSet)
	json.Unmarshal([]byte(s), &FinalSet)
	if stdout {
		fmt.Printf("Final combined traffic export: %d records\r\n", len(FinalSet))
	}

	// Combine sets and return
	return combineTrafficBodies(finalJSONSet), nil

}

func combineTrafficBodies(traffic []string) string {
	combinedTraffic := []string{}
	for _, t := range traffic {
		// Skip if no entries
		if len(t) < 3 {
			continue
		}
		// Remove the first bracket
		s := strings.TrimPrefix(t, "[")
		s = strings.TrimSuffix(s, "]")
		combinedTraffic = append(combinedTraffic, s)
	}
	return fmt.Sprintf("%s%s%s", "[", strings.Join(combinedTraffic, ","), "]")

}

func iterateOverPorts(p PCE, tq TrafficQuery, protoResults []TrafficAnalysis, stdout bool) (string, error) {
	// The future exclude is used in the last query to cover any target protocol ports we didn't see originally
	futureExclude := [][2]int{}

	// Get what protocol we are iterating. If we are iterating TCP, we exlude all UDP from final query and vice-versa
	var proto string
	var protoNum int
	if protoResults[0].ExpSrv.Proto == 6 {
		proto = "TCP"
		protoNum = 6
		futureExclude = append(futureExclude, [2]int{0, 17})
	}
	if protoResults[0].ExpSrv.Proto == 17 {
		proto = "UDP"
		protoNum = 17
		futureExclude = append(futureExclude, [2]int{0, 6})
	}

	// Clear the exclude
	tq.PortProtoExclude = [][2]int{}

	// Make our port map to know what we need to iterate over
	ports := make(map[int]int)
	for _, t := range protoResults {
		ports[t.ExpSrv.Port] = 6
	}

	// Iterate through each port
	iterator := 0
	jsonSlice := []string{}
	for i := range ports {
		iterator++
		if stdout {
			fmt.Printf("\r                                            ")
			fmt.Printf("\rQuerying %s Port %d - %d of %d (%d%%)", proto, i, iterator, len(ports), int(iterator*100/len(ports)))
		}
		tq.PortProtoInclude = [][2]int{[2]int{i, protoNum}}
		_, a, err := p.GetTrafficAnalysis(tq)
		if err != nil {
			return "", err
		}
		jsonSlice = append(jsonSlice, a.RespBody)
		futureExclude = append(futureExclude, [2]int{i, protoNum})
	}

	// Run one more time exclude all previous queries
	if stdout {
		fmt.Printf("\r                                                 ")
		fmt.Printf("\rCompleted querying %d %s ports\r\n", len(ports), proto)
	}
	tq.PortProtoInclude = [][2]int{}
	tq.PortProtoExclude = futureExclude // Problem is right here. Grabbing UDP
	_, a, err := p.GetTrafficAnalysis(tq)
	if stdout {
		fmt.Printf("Completed querying all other %s ports not included in original set.\r\n", proto)
	}
	if err != nil {
		return "", err
	}
	jsonSlice = append(jsonSlice, a.RespBody)

	return combineTrafficBodies(jsonSlice), nil
}

// UploadTraffic uploads a csv to the PCE with traffic flows.
func (p *PCE) UploadTraffic(filename string) (FlowUploadResp, APIResponse, error) {

	// Read the CSV File
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return FlowUploadResp{}, APIResponse{}, fmt.Errorf("upload traffic - opening file - %s", err)
	}
	body := bytes.NewReader(f)

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/agents/bulk_traffic_flows")
	if err != nil {
		return FlowUploadResp{}, APIResponse{}, fmt.Errorf("upload traffic - building api url - %s", err)
	}

	// Build the Request
	req, err := http.NewRequest("POST", apiURL.String(), body)
	req.SetBasicAuth(p.User, p.Key)

	// Make HTTP Request
	client := http.Client{}
	if p.DisableTLSChecking == true {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return FlowUploadResp{}, APIResponse{}, err
	}

	// Process response
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return FlowUploadResp{}, APIResponse{}, err
	}

	// Put relevant response info into struct
	response := APIResponse{RespBody: string(data[:]), StatusCode: resp.StatusCode, Header: resp.Header, Request: resp.Request}

	// Check for a 200 response code
	if strconv.Itoa(resp.StatusCode)[0:1] != "2" {
		return FlowUploadResp{}, response, errors.New("http status code of " + strconv.Itoa(response.StatusCode))
	}

	// Unmarshal response
	var flowResults FlowUploadResp
	json.Unmarshal([]byte(response.RespBody), &flowResults)

	// Return data and nil error
	return flowResults, response, nil
}
