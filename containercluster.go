package illumioapi

import "strings"

// ContainerCluster represents a Kubernetes cluster
type ContainerCluster struct {
	Href             string  `json:"href,omitempty"`
	Name             string  `json:"name,omitempty"`
	Description      *string `json:"description,omitempty"`
	ContainerRuntime string  `json:"container_runtime,omitempty"`
	ManagerType      string  `json:"manager_type,omitempty"`
	Online           *bool   `json:"online,omitempty"`
	KubelinkVersion  string  `json:"kubelink_version,omitempty"`
	PceFqdn          string  `json:"pce_fqdn,omitempty"`
}

// GetContainerClusters returns a slice of ContainerCluster in the PCE.
// queryParameters can be used for filtering in the form of ["parameter"]="value".
// The first API call to the PCE does not use the async option.
// If the slice length is >=500, it re-runs with async.
func (p *PCE) GetContainerClusters(queryParameters map[string]string) (api APIResponse, err error) {
	api, err = p.GetCollection("container_clusters", false, queryParameters, &p.ContainerClustersSlice)
	if len(p.ContainerClustersSlice) >= 500 {
		p.ContainerClustersSlice = nil
		api, err = p.GetCollection("container_clusters", true, queryParameters, &p.ContainerClustersSlice)
	}
	// Load the PCE with the returned workloads
	p.ContainerClusters = make(map[string]ContainerCluster)
	for _, c := range p.ContainerClustersSlice {
		p.ContainerClusters[c.Href] = c
		p.ContainerClusters[c.Name] = c
	}
	return api, err
}

func (c *ContainerCluster) ID() string {
	s := strings.Split(c.Href, "/")
	return s[len(s)-1]
}
