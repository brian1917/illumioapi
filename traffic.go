package illumioapi

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// TrafficAnalysisRequest is is to the traffic analysis POST request
type TrafficAnalysisRequest struct {
	QueryName                       *string           `json:"query_name,omitempty"` //Option to send blank query name
	Sources                         *SrcOrDst         `json:"sources"`
	Destinations                    *SrcOrDst         `json:"destinations"`
	ExplorerServices                *ExplorerServices `json:"services"`
	StartDate                       time.Time         `json:"start_date,omitempty"`
	EndDate                         time.Time         `json:"end_date,omitempty"`
	PolicyDecisions                 *[]string         `json:"policy_decisions"`
	MaxResults                      int               `json:"max_results,omitempty"`
	SourcesDestinationsQueryOp      string            `json:"sources_destinations_query_op,omitempty"`
	ExcludeWorkloadsFromIPListQuery *bool             `json:"exclude_workloads_from_ip_list_query,omitempty"`
}

// Sources represents the sources query portion of the explorer API
type SrcOrDst struct {
	Include [][]IncludeOrExclude `json:"include"`
	Exclude []IncludeOrExclude   `json:"exclude"`
}

// ExplorerServices represent services to be included or excluded in the explorer query
type ExplorerServices struct {
	Include []IncludeOrExclude `json:"include"`
	Exclude []IncludeOrExclude `json:"exclude"`
}

// PortProtos represents the ports and protocols query portion of the exporer API
type PortProtos struct {
	Include []IncludeOrExclude `json:"include"`
	Exclude []IncludeOrExclude `json:"exclude"`
}

// IncludeOrExclude is used in traffic queries.
type IncludeOrExclude struct {
	Actors         string     `json:"actors,omitempty"`
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
	IP       string     `json:"ip"`
	Workload *Workload  `json:"workload,omitempty"`
	FQDN     string     `json:"fqdn,omitempty"`
	IPLists  *[]*IPList `json:"ip_lists"`
}

// Src is the consumer workload details
type Src struct {
	IP       string     `json:"ip"`
	Workload *Workload  `json:"workload,omitempty"`
	FQDN     string     `json:"fqdn,omitempty"`
	IPLists  *[]*IPList `json:"ip_lists"`
}

// TimestampRange is used to limit queries ranges for the flow detected
type TimestampRange struct {
	FirstDetected string `json:"first_detected"`
	LastDetected  string `json:"last_detected"`
}

// TrafficQuery is the struct to be passed to the GetTrafficAnalysis function
type TrafficQuery struct {
	SourcesInclude      [][]string
	SourcesExclude      []string
	DestinationsInclude [][]string
	DestinationsExclude []string
	// PortProtoInclude and PortProtoExclude entries should be in the format of [port, protocol]
	// Example [80, 6] is Port 80 TCP.
	PortProtoInclude [][2]int
	PortProtoExclude [][2]int
	// PortRangeInclude and PortRangeExclude entries should be of the format [fromPort, toPort, protocol]
	// Example - [1000, 2000, 6] is Ports 1000-2000 TCP.
	PortRangeInclude                [][3]int
	PortRangeExclude                [][3]int
	ProcessInclude                  []string
	WindowsServiceInclude           []string
	ProcessExclude                  []string
	WindowsServiceExclude           []string
	StartTime                       time.Time
	EndTime                         time.Time
	PolicyStatuses                  []string
	MaxFLows                        int
	TransmissionExcludes            []string // Example: []string{"broadcast", "multicast"} will only get unicast traffic
	QueryOperator                   string   // Value should be "and" or "or". "and" is used by default
	ExcludeWorkloadsFromIPListQuery bool     // The PCE UI uses a value of true by default
}

// RegionsItems
type RegionsItems struct {
	FlowsCount   int    `json:"flows_count,omitempty"`   // region result count after query limits and RBAC filtering are applied
	MatchesCount int    `json:"matches_count,omitempty"` // region query result count
	PceFqdn      string `json:"pce_fqdn"`                // fqdn of PCE region
	Responded    bool   `json:"responded"`               // supercluster region responded with query results
}

// Root Asynchronous explorer query status
type AsyncTrafficQuery struct {
	CreatedAt       string                  `json:"created_at,omitempty"` // Timestamp in UTC when this query was created
	CreatedBy       *Href                   `json:"created_by,omitempty"`
	FlowsCount      int                     `json:"flows_count,omitempty"`   // result count after query limits and RBAC filtering are applied
	Href            string                  `json:"href,omitempty"`          // Query URI
	MatchesCount    int                     `json:"matches_count,omitempty"` // query result count
	QueryParameters *TrafficAnalysisRequest `json:"query_parameters"`        // Explorer query parameters
	Regions         *[]RegionsItems         `json:"regions,omitempty"`       // Region-specific response metadata
	Result          string                  `json:"result,omitempty"`        // Result download URI, availble only if status is completed
	Status          string                  `json:"status"`                  // Current query status
	UpdatedAt       string                  `json:"updated_at,omitempty"`    // Timestamp in UTC when this async query was last updated.
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

// buildTrafficAnalysisRequest is an internal function that builds the traffic query function
func buildTrafficAnalysisRequest(q TrafficQuery) (TrafficAnalysisRequest, error) {
	// Includes

	// Create the two Include slices using make so JSON is marshaled with empty arrays and not null values to meet Illumio API spec.
	sourceInc := make([][]IncludeOrExclude, 0)
	destInc := make([][]IncludeOrExclude, 0)

	// Populate a slice with our provided query lists
	includeQueryLists := [][][]string{q.SourcesInclude, q.DestinationsInclude}

	// Create a slice of pointers to the newly created slices. So we can fill in the iterations.
	inclTargets := []*[][]IncludeOrExclude{&sourceInc, &destInc}

	// Iterate through the q.SourcesInclude (n=0) and q.DestinationsInclude (n=1)
	for n, includeQueryList := range includeQueryLists {

		// Iterate through each includeArray
		for _, includeArray := range includeQueryList {
			if len(includeArray) > 0 {

				// Create the inside array
				insideInc := []IncludeOrExclude{}

				// Iterate through each and fill the inside Array
				for _, a := range includeArray {
					switch ParseObjectType(a) {
					case "label":
						insideInc = append(insideInc, IncludeOrExclude{Label: &Label{Href: a}})
					case "workload":
						insideInc = append(insideInc, IncludeOrExclude{Workload: &Workload{Href: a}})
					case "iplist":
						insideInc = append(insideInc, IncludeOrExclude{IPList: &IPList{Href: a}})
					case "unknown":
						if net.ParseIP(a) == nil {
							v := "source"
							if n != 0 {
								v = "destination"
							}
							return TrafficAnalysisRequest{}, fmt.Errorf("provided %s include is not label, workload, iplist, or ip address", v)
						}
						insideInc = append(insideInc, IncludeOrExclude{IPAddress: &IPAddress{Value: a}})
					}
				}

				// Append the inside array to the correct outter array
				*inclTargets[n] = append(*inclTargets[n], insideInc)
			} else {
				*inclTargets[n] = append(*inclTargets[n], make([]IncludeOrExclude, 0))
			}

		}
	}

	// Excludes

	// Create the two Exclude slices using make so JSON is marshaled with empty arrays and not null values to meet Illumio API spec.
	sourceExcl, destExcl := make([]IncludeOrExclude, 0), make([]IncludeOrExclude, 0)

	// Create a slice of pointers to the newly created slices. So we can fill in the iterations.
	exclTargets := []*[]IncludeOrExclude{&sourceExcl, &destExcl}

	// Populate a slice with our provided query lists
	excludeQueryLists := [][]string{q.SourcesExclude, q.DestinationsExclude}

	for n, excludeQueryList := range excludeQueryLists {
		var pceObjType string
		for i, exclude := range excludeQueryList {
			// Set the type based on the first entry
			if i == 0 {
				pceObjType = ParseObjectType(exclude)
			}
			// If it's a different object type, we need to error.
			if ParseObjectType(exclude) != pceObjType {
				v := "source"
				if n != 0 {
					v = "destination"
				}
				return TrafficAnalysisRequest{}, fmt.Errorf("provided %s excludes are not of the same type", v)
			}

			// Add to the exclude
			switch pceObjType {
			case "label":
				*exclTargets[n] = append(*exclTargets[n], IncludeOrExclude{Label: &Label{Href: exclude}})
			case "workload":
				*exclTargets[n] = append(*exclTargets[n], IncludeOrExclude{Workload: &Workload{Href: exclude}})
			case "iplist":
				*exclTargets[n] = append(*exclTargets[n], IncludeOrExclude{IPList: &IPList{Href: exclude}})
			case "unknown":
				if net.ParseIP(exclude) == nil {
					v := "source"
					if n != 0 {
						v = "destination"
					}
					return TrafficAnalysisRequest{}, fmt.Errorf("provided %s exclude is not label, workload, iplist, or ip address", v)
				}
				*exclTargets[n] = append(*exclTargets[n], IncludeOrExclude{IPAddress: &IPAddress{Value: exclude}})
			}
		}
	}

	// Services

	// Create the array
	serviceInclude := make([]IncludeOrExclude, 0)
	serviceExclude := make([]IncludeOrExclude, 0)

	// Port and protocol - include
	for _, portProto := range q.PortProtoInclude {
		serviceInclude = append(serviceInclude, IncludeOrExclude{Port: portProto[0], Proto: portProto[1]})
	}

	// Port and protocol - exclude
	for _, portProto := range q.PortProtoExclude {
		serviceExclude = append(serviceExclude, IncludeOrExclude{Port: portProto[0], Proto: portProto[1]})
	}

	// Port Range - include
	for _, portRange := range q.PortRangeInclude {
		serviceInclude = append(serviceInclude, IncludeOrExclude{Port: portRange[0], ToPort: portRange[1], Proto: portRange[2]})
	}

	// Port Range - exclude
	for _, portRange := range q.PortRangeExclude {
		serviceExclude = append(serviceExclude, IncludeOrExclude{Port: portRange[0], ToPort: portRange[1], Proto: portRange[2]})
	}

	// Process - include
	for _, process := range q.ProcessInclude {
		serviceInclude = append(serviceInclude, IncludeOrExclude{Process: process})
	}

	// Process - exclude
	for _, process := range q.ProcessExclude {
		serviceExclude = append(serviceExclude, IncludeOrExclude{Process: process})
	}

	// Windows Service - include
	for _, winSrv := range q.WindowsServiceInclude {
		serviceInclude = append(serviceInclude, IncludeOrExclude{WindowsService: winSrv})
	}

	// Windows Service - exclude
	for _, winSrv := range q.WindowsServiceExclude {
		serviceExclude = append(serviceExclude, IncludeOrExclude{WindowsService: winSrv})
	}

	// Traffic transmission type
	for _, excl := range q.TransmissionExcludes {
		destExcl = append(destExcl, IncludeOrExclude{Transmission: excl})
	}

	// Build the TrafficAnalysisRequest struct
	traffic := TrafficAnalysisRequest{
		Sources: &SrcOrDst{
			Include: sourceInc,
			Exclude: sourceExcl},
		Destinations: &SrcOrDst{
			Include: destInc,
			Exclude: destExcl},
		ExplorerServices: &ExplorerServices{
			Include: serviceInclude,
			Exclude: serviceExclude},
		PolicyDecisions: &q.PolicyStatuses,
		StartDate:       q.StartTime,
		EndDate:         q.EndTime,
		MaxResults:      q.MaxFLows}

	return traffic, nil

}

// GetTrafficAnalysis gets flow data from Explorer.
func (p *PCE) GetTrafficAnalysis(q TrafficQuery) (returnedTraffic []TrafficAnalysis, api APIResponse, err error) {

	// Build the traffic query object
	traffic, err := buildTrafficAnalysisRequest(q)
	if err != nil {
		return nil, APIResponse{}, err
	}

	// Get the PCE Version
	_, api, err = p.GetVersion()
	if err != nil {
		return nil, api, err
	}

	// Adjust the ExcludeWorkloads from IP List Query
	if p.Version.Major > 19 {
		traffic.ExcludeWorkloadsFromIPListQuery = &q.ExcludeWorkloadsFromIPListQuery
	} else {
		traffic.ExcludeWorkloadsFromIPListQuery = nil
	}

	// We are going to edit it here so we can omit if necessary
	if strings.ToLower(q.QueryOperator) == "or" || strings.ToLower(q.QueryOperator) == "and" {
		traffic.SourcesDestinationsQueryOp = strings.ToLower(q.QueryOperator)
	}

	return p.CreateTrafficRequest(traffic)
}

// GetTrafficAnalysisCsv gets flow data from Explorer in CSV Format.
func (p *PCE) GetTrafficAnalysisCsv(q TrafficQuery) (returnedTraffic [][]string, api APIResponse, err error) {

	// Get the version
	if p.Version.Major == 0 {
		_, api, err := p.GetVersion()
		if err != nil {
			return nil, api, fmt.Errorf("error getting version - %s. api response is from get version", err)
		}
	}

	if p.Version.Major < 21 || (p.Version.Major == 21 && p.Version.Minor < 2) {
		return returnedTraffic, APIResponse{}, fmt.Errorf("pce version does not support csv queries")
	}
	verboseLogf("GetTrafficAnalysisCsv - pce version: %s", p.Version.LongDisplay)

	traffic, err := buildTrafficAnalysisRequest(q)
	if err != nil {
		return nil, APIResponse{}, err
	}

	// We are going to edit it here so we can omit if necessary
	if strings.ToLower(q.QueryOperator) == "or" || strings.ToLower(q.QueryOperator) == "and" {
		traffic.SourcesDestinationsQueryOp = strings.ToLower(q.QueryOperator)
	}

	return p.CreateTrafficRequestCsv(traffic)
}

// CreateTrafficRequest makes a traffic request and waits for the results
func (p *PCE) CreateTrafficRequest(t TrafficAnalysisRequest) (returnedTraffic []TrafficAnalysis, api APIResponse, err error) {
	// Get the version
	if p.Version.Major == 0 {
		_, api, err := p.GetVersion()
		if err != nil {
			return nil, api, fmt.Errorf("error getting version - %s. api response is from get version", err)
		}
	}

	// If the version is less than 21.2, use the old api endpoint
	if p.Version.Major < 21 || (p.Version.Major == 21 && p.Version.Minor < 2) {
		// Clear the query name
		t.QueryName = nil
		// Run the API
		verboseLog("CreateTrafficRequest - using old api endpoint due to PCE version: /traffic_flows/traffic_analysis_queries")
		api, err = p.Post("/traffic_flows/traffic_analysis_queries", &t, &returnedTraffic)
		return returnedTraffic, api, err
	}

	asyncQuery, api, err := p.CreateAsyncTrafficRequest(t)
	if err != nil {
		return returnedTraffic, api, err
	}

	// Check queries
	for {
		var aq AsyncTrafficQuery
		verboseLog("CreateTrafficRequest - using new aysnc traffic api")
		api, err = p.GetHref(asyncQuery.Href, &aq)
		if err != nil {
			return nil, api, err
		}
		verboseLogf("CreateTrafficRequest - aq.href: %s; aq.Status: %s", aq.Href, aq.Status)
		if aq.Href == asyncQuery.Href && aq.Status == "completed" {
			verboseLog("CreateTrafficRequest - getting async results json...")
			return p.GetAsyncQueryResults(aq)
		}
		time.Sleep(3 * time.Second)
	}
}

// CreateTrafficRequest makes a traffic request and waits for the results
func (p *PCE) CreateTrafficRequestCsv(t TrafficAnalysisRequest) (returnedTraffic [][]string, api APIResponse, err error) {
	// Get the version
	if p.Version.Major == 0 {
		_, api, err := p.GetVersion()
		if err != nil {
			return nil, api, fmt.Errorf("error getting version - %s. api response is from get version", err)
		}
	}

	// If the version is less than 21.2, use the old api endpoint
	if p.Version.Major < 21 || (p.Version.Major == 21 && p.Version.Minor < 2) {
		return returnedTraffic, api, fmt.Errorf("pce version does not support querying csv results")
	}

	asyncQuery, api, err := p.CreateAsyncTrafficRequest(t)
	if err != nil {
		return returnedTraffic, api, err
	}

	// Check queries
	for {
		var aq AsyncTrafficQuery
		verboseLog("CreateTrafficRequestCsv - using new aysnc traffic api")
		api, err = p.GetHref(asyncQuery.Href, &aq)
		if err != nil {
			return nil, api, err
		}
		verboseLogf("aq.href: %s; aq.Status: %s", aq.Href, aq.Status)
		if aq.Href == asyncQuery.Href && aq.Status == "completed" {
			verboseLog("CreateTrafficRequestCsv - getting async results csv")
			return p.GetAsyncQueryResultsCsv(aq)
		}
		time.Sleep(3 * time.Second)
	}
}

// CreateAsyncTrafficRequest makes a traffic request and returns the async query to look up later
func (p *PCE) CreateAsyncTrafficRequest(t TrafficAnalysisRequest) (asyncQuery AsyncTrafficQuery, api APIResponse, err error) {
	// Make sure a queryname is provided
	if t.QueryName == nil {
		t.QueryName = Ptr("")
	}
	api, err = p.Post("traffic_flows/async_queries", &t, &asyncQuery)
	return asyncQuery, api, err
}

func (p *PCE) GetAsyncQueries(queryParameters map[string]string) (asyncQueries []AsyncTrafficQuery, api APIResponse, err error) {
	api, err = p.GetCollection("traffic_flows/async_queries", false, queryParameters, &asyncQueries)
	// Async Queries does not use the async collection
	return asyncQueries, api, err
}

func (p *PCE) GetAsyncQueryResults(aq AsyncTrafficQuery) (returnedTraffic []TrafficAnalysis, api APIResponse, err error) {
	result := strings.TrimPrefix(aq.Result, fmt.Sprintf("/orgs/%d/", p.Org))
	api, err = p.GetCollectionHeaders(result, false, nil, map[string]string{"Accept": "application/json"}, &returnedTraffic)
	return returnedTraffic, api, err
}

func (p *PCE) GetAsyncQueryResultsCsv(aq AsyncTrafficQuery) (csvData [][]string, api APIResponse, err error) {
	result := strings.TrimPrefix(aq.Result, fmt.Sprintf("/orgs/%d/", p.Org))
	api, err = p.GetCollection(result, false, nil, nil)
	if api.StatusCode < 200 || api.StatusCode > 299 {
		return csvData, api, fmt.Errorf("api status code %d returned", api.StatusCode)
	}
	if err != nil {
		return csvData, api, err
	}

	reader := csv.NewReader(strings.NewReader(api.RespBody))
	// Iterate through CSV entries
	for {
		// Read the line
		line, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, api, err
		}
		// Append
		csvData = append(csvData, line)
	}

	return csvData, api, nil
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
		// Read the line
		line, err := reader.Read()
		if err == io.EOF {
			break
		}

		// Increment the counter
		i++

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
	apiURL, err := url.Parse("https://" + p.cleanFQDN() + ":" + strconv.Itoa(p.Port) + "/api/v2/orgs/" + strconv.Itoa(p.Org) + "/agents/bulk_traffic_flows")
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
		api, err := p.httpReq("POST", apiURL.String(), []byte(strings.Join(fs, "\n")), false, nil)
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

// DedupeExplorerTraffic takes two traffic responses and returns a de-duplicated result set
func DedupeExplorerTraffic(first, second []TrafficAnalysis) []TrafficAnalysis {
	var new []TrafficAnalysis

	firstMap := make(map[string]bool)
	for _, entry := range first {
		firstMap[createExplorerMapKey(entry)] = true
		new = append(new, entry)
	}

	for _, entry := range second {
		if !firstMap[createExplorerMapKey(entry)] {
			new = append(new, entry)
		}
	}

	return new
}

func createExplorerMapKey(entry TrafficAnalysis) string {
	key := entry.Dst.FQDN + entry.Dst.IP
	if entry.Dst.Workload != nil {
		key = key + PtrToVal(entry.Dst.Workload.Hostname)
	}
	key = key + strconv.Itoa(entry.ExpSrv.Port) + entry.ExpSrv.Process + strconv.Itoa(entry.ExpSrv.Proto) + entry.ExpSrv.User + entry.ExpSrv.WindowsService + strconv.Itoa(entry.NumConnections) + entry.PolicyDecision + entry.Src.FQDN + entry.Src.IP
	if entry.Src.Workload != nil {
		key = key + PtrToVal(entry.Src.Workload.Hostname)
	}
	key = key + entry.TimestampRange.FirstDetected + entry.TimestampRange.LastDetected + entry.Transmission
	return key
}

func CreateIncludeOrExclude(objects []string, include bool) (IncOrExc []IncludeOrExclude, err error) {
	for _, object := range objects {
		switch ParseObjectType(object) {
		case "label":
			IncOrExc = append(IncOrExc, IncludeOrExclude{Label: &Label{Href: object}})
		case "workload":
			IncOrExc = append(IncOrExc, IncludeOrExclude{Workload: &Workload{Href: object}})
		case "iplist":
			IncOrExc = append(IncOrExc, IncludeOrExclude{IPList: &IPList{Href: object}})
		case "unknown":
			if net.ParseIP(object) == nil {
				return nil, errors.New("provided object is not label, workload, iplist, or ip address")
			} else {
				IncOrExc = append(IncOrExc, IncludeOrExclude{IPAddress: &IPAddress{Value: object}})
			}
		}
	}
	return IncOrExc, nil
}
