package illumioapi

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// TrafficAnalysisRequest represents the payload object for the traffic analysis POST request
type TrafficAnalysisRequest struct {
	Sources                    Sources          `json:"sources"`
	Destinations               Destinations     `json:"destinations"`
	ExplorerServices           ExplorerServices `json:"services"`
	StartDate                  time.Time        `json:"start_date,omitempty"`
	EndDate                    time.Time        `json:"end_date,omitempty"`
	PolicyDecisions            []string         `json:"policy_decisions"`
	MaxResults                 int              `json:"max_results,omitempty"`
	SourcesDestinationsQueryOp string           `json:"sources_destinations_query_op,omitempty"`
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
	IPList         *IPList    `json:"ip_list,omitempty"`
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
	IPList         *IPList    `json:"ip_list,omitempty"`
	IPAddress      *IPAddress `json:"ip_address,omitempty"`
	Port           int        `json:"port,omitempty"`
	ToPort         int        `json:"to_port,omitempty"`
	Proto          int        `json:"proto,omitempty"`
	Process        string     `json:"process_name,omitempty"`
	WindowsService string     `json:"windows_service_name,omitempty"`
	Transmission   string     `json:"transmission,omitempty"`
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
	Transmission   string          `json:"transmission"`
}

// ExpSrv is a service in the explorer response
type ExpSrv struct {
	Port           int    `json:"port,omitempty"`
	Proto          int    `json:"proto,omitempty"`
	Process        string `json:"process_name,omitempty"`
	User           string `json:"user_name,omitempty"`
	WindowsService string `json:"windows_service_name,omitempty"`
}

// Dst is the provider workload details
type Dst struct {
	IP       string    `json:"ip"`
	Workload *Workload `json:"workload,omitempty"`
	FQDN     string    `json:"fqdn,omitempty"`
}

// Src is the consumer workload details
type Src struct {
	IP       string    `json:"ip"`
	Workload *Workload `json:"workload,omitempty"`
	FQDN     string    `json:"fqdn,omitempty"`
}

// TimestampRange is used to limit queries ranges for the flow detected
type TimestampRange struct {
	FirstDetected string `json:"first_detected"`
	LastDetected  string `json:"last_detected"`
}

// TrafficQuery is the struct to be passed to the GetTrafficAnalysis function
type TrafficQuery struct {
	SourcesInclude      []string
	SourcesExclude      []string
	DestinationsInclude []string
	DestinationsExclude []string
	// PortProtoInclude and PortProtoExclude entries should be in the format of [port, protocol]
	// Example [80, 6] is Port 80 TCP.
	PortProtoInclude [][2]int
	PortProtoExclude [][2]int
	// PortRangeInclude and PortRangeExclude entries should be of the format [fromPort, toPort, protocol]
	// Example - [1000, 2000, 6] is Ports 1000-2000 TCP.
	PortRangeInclude      [][3]int
	PortRangeExclude      [][3]int
	ProcessInclude        []string
	WindowsServiceInclude []string
	ProcessExclude        []string
	WindowsServiceExclude []string
	StartTime             time.Time
	EndTime               time.Time
	PolicyStatuses        []string
	MaxFLows              int
	TransmissionExcludes  []string // Example: []string{"broadcast", "multicast"} will only get unicast traffic
	QueryOperator         string   // Value should be "and" or "or". "and" is used by default
}

// FlowUploadResp is the response from the traffic upload API
type FlowUploadResp struct {
	NumFlowsReceived int       `json:"num_flows_received"`
	NumFlowsFailed   int       `json:"num_flows_failed"`
	FailedFlows      []*string `json:"failed_flows,omitempty"`
}

// UploadFlowResults is the struct returned to the user when using the pce.UploadTraffic() method
type UploadFlowResults struct {
	FlowResps       []FlowUploadResp
	APIResps        []APIResponse
	TotalFlowsInCSV int
}

// GetTrafficAnalysis gets flow data from Explorer.
func (p *PCE) GetTrafficAnalysis(q TrafficQuery) ([]TrafficAnalysis, APIResponse, error) {
	var api APIResponse

	// Initialize arrays using "make" so JSON is marshaled with empty arrays and not null values to meet Illumio API spec
	sourceInc := make([]Include, 0)
	destInc := make([]Include, 0)

	sourceExcl := make([]Exclude, 0)
	destExcl := make([]Exclude, 0)

	// Process source include, destination include, source exclude, and destination exclude
	queryLists := [][]string{q.SourcesInclude, q.DestinationsInclude, q.SourcesExclude, q.DestinationsExclude}

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

				// IP Lists
			} else if strings.Contains(queryList[0], "iplist") == true {
				for _, iplist := range queryLists[i] {
					queryIPList := IPList{Href: iplist}
					switch i {
					case 0:
						sourceInc = append(sourceInc, Include{IPList: &queryIPList})
					case 1:
						destInc = append(destInc, Include{IPList: &queryIPList})
					case 2:
						sourceExcl = append(sourceExcl, Exclude{IPList: &queryIPList})
					case 3:
						destExcl = append(destExcl, Exclude{IPList: &queryIPList})
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
	for _, portProto := range q.PortProtoInclude {
		serviceInclude = append(serviceInclude, Include{Port: portProto[0], Proto: portProto[1]})
	}

	// Port and protocol - exclude
	for _, portProto := range q.PortProtoExclude {
		serviceExclude = append(serviceExclude, Exclude{Port: portProto[0], Proto: portProto[1]})
	}

	// Port Range - include
	for _, portRange := range q.PortRangeInclude {
		serviceInclude = append(serviceInclude, Include{Port: portRange[0], ToPort: portRange[1], Proto: portRange[2]})
	}

	// Port Range - exclude
	for _, portRange := range q.PortRangeExclude {
		serviceExclude = append(serviceExclude, Exclude{Port: portRange[0], ToPort: portRange[1], Proto: portRange[2]})
	}

	// Process - include
	for _, process := range q.ProcessInclude {
		serviceInclude = append(serviceInclude, Include{Process: process})
	}

	// Process - exclude
	for _, process := range q.ProcessExclude {
		serviceExclude = append(serviceExclude, Exclude{Process: process})
	}

	// Windows Service - include
	for _, winSrv := range q.WindowsServiceInclude {
		serviceInclude = append(serviceInclude, Include{WindowsService: winSrv})
	}

	// Windows Service - exclude
	for _, winSrv := range q.WindowsServiceExclude {
		serviceExclude = append(serviceExclude, Exclude{WindowsService: winSrv})
	}

	// Traffic transmission type
	for _, excl := range q.TransmissionExcludes {
		destExcl = append(destExcl, Exclude{Transmission: excl})
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
		PolicyDecisions: q.PolicyStatuses,
		StartDate:       q.StartTime,
		EndDate:         q.EndTime,
		MaxResults:      q.MaxFLows}

	// We are going to edit it here so we can omit if necessary
	if strings.ToLower(q.QueryOperator) == "or" || strings.ToLower(q.QueryOperator) == "and" {
		traffic.SourcesDestinationsQueryOp = strings.ToLower(q.QueryOperator)
	}

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

// IterateTraffic returns an array of traffic analysis .
// The iterative query starts by running a blank explorer query. If the results are over 90K, it queries again by TCP, UDP, and other.
// If either protocol-specific query is over 90K, it queries again by TCP and UDP port.
func (p *PCE) IterateTraffic(q TrafficQuery, stdout bool) ([]TrafficAnalysis, error) {
	i, err := p.IterateTrafficJString(q, stdout)
	if err != nil {
		return nil, err
	}
	var t []TrafficAnalysis
	json.Unmarshal([]byte(i), &t)
	if stdout {
		fmt.Printf("[INFO] - Final combined traffic export: %d records\r\n", len(t))
	}
	return t, nil

}

// Threshold is the value set to iterate
var Threshold int

// IterateTrafficJString returns the combined JSON output from an iterative exlplorer query.
// The iterative query starts by running a blank explorer query. If the results are over 90K, it queries again by TCP, UDP, and other.
// If either protocol-specific query is over 90K, it queries again by TCP and UDP port.
func (p *PCE) IterateTrafficJString(q TrafficQuery, stdout bool) (string, error) {

	// If the threshold isn't set by app, use 90000
	if Threshold == 0 {
		Threshold = 90000
	}

	// Get all explorer data to see where we are starting
	t, a, _ := p.GetTrafficAnalysis(q)
	if stdout {
		fmt.Printf("[INFO] - Initial traffic query: %d records\r\n", len(t))
	}

	// If the length is under Threshold return it and be done
	if len(t) < Threshold {
		if stdout {
			fmt.Println("[INFO] - Traffic querying completed")
		}
		return a.RespBody, nil
	}

	if stdout {
		fmt.Printf("[INFO] - Traffic records close to threshold (%d) - beginning query by protocol...\r\n", Threshold)
	}

	// If we are over Threshold, run the query again for TCP, UDP, and everything else.
	// TCP
	q.PortProtoInclude = [][2]int{[2]int{0, 6}}
	tcpT, tcpA, err := p.GetTrafficAnalysis(q)
	if err != nil {
		return "", err
	}
	if stdout {
		fmt.Printf("[INFO] - TCP traffic query: %d records\r\n", len(tcpT))
	}
	// UDP
	q.PortProtoInclude = [][2]int{[2]int{0, 17}}
	udpT, udpA, err := p.GetTrafficAnalysis(q)
	if err != nil {
		return "", err
	}
	if stdout {
		fmt.Printf("[INFO] - UDP traffic query: %d records\r\n", len(udpT))
	}
	// Other Protos
	q.PortProtoInclude = nil
	q.PortProtoExclude = [][2]int{[2]int{0, 6}, [2]int{0, 17}}
	otherProtoT, otherProtoA, err := p.GetTrafficAnalysis(q)
	if err != nil {
		return "", err
	}
	if stdout {
		fmt.Printf("[INFO] - Other traffic query: %d records\r\n", len(otherProtoT))
	}

	// Create a variable to hold final JSON strings and start with other protocols
	finalJSONSet := []string{otherProtoA.RespBody}

	// Process if TCP is over Threshold
	if len(tcpT) > Threshold {
		if stdout {
			fmt.Printf("[INFO] - TCP entries close to threshold (%d), querying by TCP port...\r\n", Threshold)
		}
		q.PortProtoInclude = [][2]int{[2]int{0, 6}}
		q.PortProtoExclude = nil
		s, err := iterateOverPorts(*p, q, tcpT, stdout)
		if err != nil {
			return "", err
		}
		finalJSONSet = append(finalJSONSet, s)
	} else {
		finalJSONSet = append(finalJSONSet, tcpA.RespBody)
	}

	// Process if UDP is over Threshold
	if len(udpT) > Threshold {
		if stdout {
			fmt.Printf("[INFO] - UDP entries close to threshold (%d), querying by UDP port...\r\n", Threshold)
		}
		q.PortProtoInclude = [][2]int{[2]int{0, 17}}
		q.PortProtoExclude = nil
		s, err := iterateOverPorts(*p, q, udpT, stdout)
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
		fmt.Printf("[INFO] - Final combined traffic export: %d records\r\n", len(FinalSet))
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
// filename should be the path to a csv file with 4 cols: src_ip, dst_ip, port, protocol (IANA numerical format 6=TCP, 17=UDP)
// When headerLine = true, the first line of the CSV is skipped.
// If there are more than 999 entries in the CSV, it creates chunks of 999
func (p *PCE) UploadTraffic(filename string, headerLine bool) (UploadFlowResults, error) {

	// Open CSV File
	file, err := os.Open(filename)
	if err != nil {
		return UploadFlowResults{}, err
	}
	defer file.Close()
	reader := csv.NewReader(clearBom(bufio.NewReader(file)))

	// Start the counters
	i := 0

	// flows slice will contain each entry from the csv. the entries will be comma separated and we'll eventually join them with line break (/n)
	var flows []string

	// Iterate through CSV entries
	for {
		// Increment the counter
		i++
		// Read the line
		line, err := reader.Read()
		if err == io.EOF {
			break
		}
		// Skip the headerline if we need to
		if headerLine && i == 1 {
			continue
		}

		if err != nil {
			return UploadFlowResults{}, err
		}
		// Append line to flows
		flows = append(flows, fmt.Sprintf("%s,%s,%s,%s", line[0], line[1], line[2], line[3]))
	}

	// Figure out how many API calls we need to make
	numAPICalls := int(math.Ceil(float64(len(flows)) / 1000))
	flowSlices := [][]string{}

	// Build the array to be passed to the API
	for i := 0; i < numAPICalls; i++ {
		// Get 1,000 elements if this is not the last array
		if (i + 1) != numAPICalls {
			flowSlices = append(flowSlices, flows[i*1000:(1+i)*1000])
			// If it's the last call, get the rest of the entries
		} else {
			flowSlices = append(flowSlices, flows[i*1000:])
		}
	}

	// Build the API URL
	apiURL, err := url.Parse("https://" + pceSanitization(p.FQDN) + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/agents/bulk_traffic_flows")
	if err != nil {
		return UploadFlowResults{}, err
	}

	// Build response struct
	t := i
	if headerLine {
		t = i - 1
	}
	results := UploadFlowResults{TotalFlowsInCSV: t}

	for _, fs := range flowSlices {

		// Call the API
		api, err := apicallNoContentType("POST", apiURL.String(), *p, []byte(strings.Join(fs, "\n")), false)
		results.APIResps = append(results.APIResps, api)
		if err != nil {
			return results, err
		}

		// Unmarshal response
		flowResults := FlowUploadResp{}
		json.Unmarshal([]byte(api.RespBody), &flowResults)
		results.FlowResps = append(results.FlowResps, flowResults)
	}

	// Return data and nil error
	return results, nil
}

// clearBOM returns an io.Reader that will skip over initial UTF-8 byte order marks.
func clearBom(r io.Reader) io.Reader {
	buf := bufio.NewReader(r)
	b, err := buf.Peek(3)
	if err != nil {
		// not enough bytes
		return buf
	}
	if b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		buf.Discard(3)
	}
	return buf
}
