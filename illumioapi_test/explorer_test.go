package illumioapi_test

// NEEDS EDITING

// func TestExplorer(t *testing.T) {

// 	startDate := time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)
// 	endDate := time.Date(2018, 7, 1, 0, 0, 0, 0, time.UTC)
// 	policyStatusList := []string{"allowed", "potentially_blocked", "blocked"}
// 	sourceIncludeList := []string{"/orgs/1/labels/68", "/orgs/1/labels/66", "/orgs/1/labels/64"}
// 	destIncludeList := []string{"/orgs/1/labels/65"}
// 	sourceExcludeList := []string{""}
// 	destExcludeList := []string{""}
// 	// inclPortProto := make([][2]int, 0)
// 	inclPortProto := [][2]int{{3306, 6}}
// 	exclPortProto := make([][2]int, 0)

// 	explorer, err := illumioapi.GetTrafficAnalysis(pce, sourceIncludeList, sourceExcludeList, destIncludeList, destExcludeList, inclPortProto, exclPortProto, startDate, endDate, policyStatusList, 10000)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Printf("%d flow(s) found with specified criteria\n", len(explorer))

// 	for _, flow := range explorer {
// 		fmt.Printf("Destination: %s (%s); Source: %s (%s)\n", flow.Dst.IP, flow.Dst.Workload.Hostname, flow.Src.IP, flow.Src.Workload.Hostname)
// 	}
// }
