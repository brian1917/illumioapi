# Illumio API Package

## Description

Go package to to act as a wrapper for the Illumio APIs.

## Included
Functions are available for the following PCE objects:

* *_Labels_*: GetAllLabels, GetLabel, CreateLabel, UpdateLabel
* *_Workloads_*: GetAllWorkloads, CreateWorkload, UpdateWorkload, BulkWorkload (create, update, or delete)
* *_Services_*: GetAllServices, CreateService, UpdateService
* *_IPLists_*: GetAllIPLists, CreateIPList, UpdateIPList
* *_BoundServics_*: GetAllBoundServices, CreateBoundService, UpdateBoundService 
* *_Pairing_*: CreatePairingProfile, CreatePairingKey
* *_LabelGroups_*: GetAllLabelGroups
* *_Rulesets_*: GetAllRuleSets
* *_Auth_*: Login
* *_Explorer_*: GetTrafficAnalysis
* *_Delete_*: DeleteHref

## Tests and Examples ##
The `illumioapi_test` package includes some tests for the package. This can also be referenced for examples on how to use some of the functions.

## GoDoc Documentation ##
Full GoDoc Documentation (output of `godoc illumioapi` is avaialble in the main directory of the repo) and below.

```
PACKAGE DOCUMENTATION

package illumioapi
    import "/Users/brianpitta/go/src/github.com/brian1917/illumioapi"


FUNCTIONS

func ProtocolList() map[int]string
    ProtocolList returns a map for the IANA protocol numbers.

TYPES

type APIResponse struct {
    RespBody   string
    StatusCode int
    Header     http.Header
    Request    *http.Request
}
    APIResponse contains the information from the response of the API

func BulkWorkload(pce PCE, workloads []Workload, method string) ([]APIResponse, error)
    BulkWorkload on Workload updates an existing workload in the Illumio PCE

    Method must be create, update, or delete

func CreatePairingKey(pce PCE, pairingProfile PairingProfile) (APIResponse, error)
    CreatePairingKey creates a pairing key from a pairing profile.

func CreatePairingProfile(pce PCE, pairingProfile PairingProfile) (APIResponse, error)
    CreatePairingProfile creates a new pairing profile in the Illumio PCE.

func DeleteHref(pce PCE, href string) (APIResponse, error)
    DeleteHref deletes an existing object in the PCE based on its href.

func UpdateBoundService(pce PCE, boundService BoundService) (APIResponse, error)
    UpdateBoundService updates an existing bound service in the Illumio PCE.

    The provided BoundService struct must include an Href. The following
    fields will be disregarded in the JSON payload because they cannot be
    updated: CreatedAt, CreatedBy, UpdateType, UpdatedAt, UpdatedBy.

func UpdateIPList(pce PCE, iplist IPList) (APIResponse, error)
    UpdateIPList updates an existing IP List in the Illumio PCE.

    The provided IPList struct must include an Href. The following fields
    will be disregarded in the JSON payload because they cannot be updated:
    CreatedAt, CreatedBy, DeletedAt, DeletedBy, UpdateType, UpdatedAt,
    UpdatedBy.

func UpdateLabel(pce PCE, label Label) (APIResponse, error)
    UpdateLabel updates an existing label in the Illumio PCE.

    The provided label struct must include an Href. The onyl values that
    will put in the JSON payload are Value, ExternalDataReference, and
    ExternalDataSet. Other values cannot be updated.

func UpdateService(pce PCE, service Service) (APIResponse, error)
    UpdateService updates an existing service object in the Illumio PCE

func UpdateWorkload(pce PCE, workload Workload) (APIResponse, error)
    UpdateWorkload updates an existing workload in the Illumio PCE

type Actors struct {
    Actors     string      `json:"actors,omitempty"`
    Label      *Label      `json:"label,omitempty"`
    LabelGroup *LabelGroup `json:"label_group,omitempty"`
    Workload   *Workload   `json:"workload,omitempty"`
}
    Actors represent Actors

type Agent struct {
    ActivePceFqdn string         `json:"active_pce_fqdn,omitempty"`
    Config        *Config        `json:"config,omitempty"`
    Href          string         `json:"href,omitempty"`
    SecureConnect *SecureConnect `json:"secure_connect,omitempty"`
    Status        *Status        `json:"status,omitempty"`
    TargetPceFqdn string         `json:"target_pce_fqdn,omitempty"`
}
    An Agent is an Agent on a Workload

type AgentHealth struct {
    AuditEvent string `json:"audit_event,omitempty"`
    Severity   string `json:"severity,omitempty"`
    Type       string `json:"type,omitempty"`
}
    AgentHealth represents the Agent Health of the Status of a Workload

type AgentHealthErrors struct {
    Errors   []string `json:"errors,omitempty"`
    Warnings []string `json:"warnings,omitempty"`
}
    AgentHealthErrors represents the Agent Health Errors of the Status of a
    Workload This is depreciated - use AgentHealth

type Authentication struct {
    AuthToken string `json:"auth_token"`
}
    Authentication represents the response of the Authenticate API

func Authenticate(pce PCE, username, password string) (Authentication, APIResponse, error)
    Authenticate produces a temporary auth token

type BoundService struct {
    ApplyTo               string     `json:"apply_to,omitempty"`
    CreatedAt             string     `json:"created_at,omitempty"`
    CreatedBy             *CreatedBy `json:"created_by,omitempty"`
    Description           string     `json:"description,omitempty"`
    ExternalDataReference string     `json:"external_data_reference,omitempty"`
    ExternalDataSet       string     `json:"external_data_set,omitempty"`
    Href                  string     `json:"href,omitempty"`
    IPOverrides           []string   `json:"ip_overrides,omitempty"`
    Labels                []*Label   `json:"labels,omitempty"`
    Name                  string     `json:"name,omitempty"`
    Service               *Service   `json:"service,omitempty"`
    UpdateType            string     `json:"update_type,omitempty"`
    UpdatedAt             string     `json:"updated_at,omitempty"`
    UpdatedBy             *UpdatedBy `json:"updated_by,omitempty"`
}
    BoundService represents a Bound Service in the Illumio PCE

func CreateBoundService(pce PCE, boundService BoundService) (BoundService, APIResponse, error)
    CreateBoundService creates a new bound service in the Illumio PCE.

func GetAllBoundServices(pce PCE, provisionStatus string) ([]BoundService, APIResponse, error)
    GetAllBoundServices returns a slice of all bound services of a specific
    provision status in the Illumio PCE.

    The pvoision status must be "draft" or "active". The first call does not
    use the async option. If the response array length is >=500, it is
    re-run enabling async.

type Config struct {
    LogTraffic               bool   `json:"log_traffic,omitempty"`
    Mode                     string `json:"mode,omitempty"`
    SecurityPolicyUpdateMode string `json:"security_policy_update_mode,omitempty"`
}
    Config represents the Configuration of an Agent on a Workload

type Consumers struct {
    Actors       string        `json:"actors,omitempty"`
    BoundService *BoundService `json:"bound_service,omitempty"`
    IPList       *IPList       `json:"ip_list,omitempty"`
    Label        *Label        `json:"label,omitempty"`
    LabelGroup   *LabelGroup   `json:"label_group,omitempty"`
    Workload     *Workload     `json:"workload,omitempty"`
}
    Consumers represent a consumer in an Illumio rule

type ConsumingSecurityPrincipals struct {
    Href string `json:"href,omitempty"`
}
    ConsumingSecurityPrincipals represent Consuming Security Principals

type CreatedBy struct {
    Href string `json:"href"`
}
    CreatedBy represents the CreatedBy property of an object

type DeletedBy struct {
    Href string `json:"href,omitempty"`
}
    DeletedBy represents the Deleted By property of an object

type Destinations struct {
    Include [][]Include `json:"include"`
    Exclude []Exclude   `json:"exclude"`
}
    Destinations represents the destination query portion of the explorer
    API

type Dst struct {
    IP       string    `json:"ip"`
    Workload *Workload `json:"workload,omitempty"`
}
    Dst Traffic flow endpoint details

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
    Exclude represents the type of objects used in an include query.

    The exclude struct should only have the following combinations: label
    only, workload only, IP address only, Port and/or protocol only.


    Example - Label and Workload cannot both be non-nil

    Example - Port and Proto can both be non-nil (e.g., port 3306 and proto
    6)

type ExpSrv struct {
    Port           int    `json:"port,omitempty"`
    Proto          int    `json:"proto,omitempty"`
    Process        string `json:"process_name,omitempty"`
    WindowsService string `json:"windows_service_name,omitempty"`
}
    ExpSrv is a service in the explorer response

type ExplorerServices struct {
    Include []Include `json:"include"`
    Exclude []Exclude `json:"exclude"`
}
    ExplorerServices represent services to be included or excluded in the
    explorer query

type IPAddress struct {
    Value string `json:"value,omitempty"`
}
    IPAddress represents an IP Address used in a query

type IPList struct {
    CreatedAt             string     `json:"created_at,omitempty"`
    CreatedBy             *CreatedBy `json:"created_by,omitempty"`
    DeletedAt             string     `json:"deleted_at,omitempty"`
    DeletedBy             *DeletedBy `json:"deleted_by,omitempty"`
    Description           string     `json:"description,omitempty"`
    ExternalDataReference string     `json:"external_data_reference,omitempty"`
    ExternalDataSet       string     `json:"external_data_set,omitempty"`
    Href                  string     `json:"href,omitempty"`
    IPRanges              []*IPRange `json:"ip_ranges,omitempty"`
    Name                  string     `json:"name,omitempty"`
    UpdatedAt             string     `json:"updated_at,omitempty"`
    UpdatedBy             *UpdatedBy `json:"updated_by,omitempty"`
}
    IPList represents an IP List in the Illumio PCE.

func CreateIPList(pce PCE, ipList IPList) (IPList, APIResponse, error)
    CreateIPList creates a new IP List in the Illumio PCE.

func GetAllIPLists(pce PCE, provisionStatus string) ([]IPList, APIResponse, error)
    GetAllIPLists returns a slice of all IP Lists of a specific provision
    status in the Illumio PCE.

    The pvoision status must be "draft" or "active". The first call does not
    use the async option. If the response array length is >=500, it is
    re-run enabling async.

type IPRange struct {
    Description string `json:"description,omitempty"`
    Exclusion   bool   `json:"exclusion,omitempty"`
    FromIP      string `json:"from_ip,omitempty"`
    ToIP        string `json:"to_ip,omitempty"`
}
    IPRange repsents one of the IP ranges of an IP List.

type IPTablesRules struct {
    Actors      []*Actors     `json:"actors"`
    Description string        `json:"description,omitempty"`
    Enabled     bool          `json:"enabled"`
    Href        string        `json:"href"`
    IPVersion   string        `json:"ip_version"`
    Statements  []*Statements `json:"statements"`
}
    IPTablesRules represent IP Table Rules

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
    Include represents the type of objects used in an include query.

    The include struct should only have the following combinations: label
    only, workload only, IP address only, Port and/or protocol only.


    Example - Label and Workload cannot both be non-nil

    Example - Port and Proto can both be non-nil (e.g., port 3306 and proto
    6)

type Interface struct {
    Address               string `json:"address,omitempty"`
    CidrBlock             int    `json:"cidr_block,omitempty"`
    DefaultGatewayAddress string `json:"default_gateway_address,omitempty"`
    FriendlyName          string `json:"friendly_name,omitempty"`
    LinkState             string `json:"link_state,omitempty"`
    Name                  string `json:"name,omitempty"`
}
    An Interface represent the Interfaces of a Workload

type Label struct {
    CreatedAt             string     `json:"created_at,omitempty"`
    CreatedBy             *CreatedBy `json:"created_by,omitempty"`
    Deleted               bool       `json:"deleted,omitempty"`
    ExternalDataReference string     `json:"external_data_reference,omitempty"`
    ExternalDataSet       string     `json:"external_data_set,omitempty"`
    Href                  string     `json:"href,omitempty"`
    Key                   string     `json:"key,omitempty"`
    UpdatedAt             string     `json:"updated_at,omitempty"`
    UpdatedBy             *UpdatedBy `json:"updated_by,omitempty"`
    Value                 string     `json:"value,omitempty"`
}
    A Label is a Label policy object in the Illumio PCE

func CreateLabel(pce PCE, label Label) (Label, APIResponse, error)
    CreateLabel creates a new Label in the Illumio PCE.

func GetAllLabels(pce PCE) ([]Label, APIResponse, error)
    GetAllLabels returns a slice of all Labels in the Illumio PCE.

    The first call does not use the async option. If the response array
    length is >=500, it is re-run enabling async.

func GetLabel(pce PCE, key, value string) (Label, APIResponse, error)
    GetLabel finds a specific Label based on the key and value.

    Will only return one Label that is an exact match.

type LabelGroup struct {
    Description           string       `json:"description,omitempty"`
    ExternalDataReference string       `json:"external_data_reference,omitempty"`
    ExternalDataSet       string       `json:"external_data_set,omitempty"`
    Href                  string       `json:"href,omitempty"`
    Key                   string       `json:"key,omitempty"`
    Labels                []*Label     `json:"labels,omitempty"`
    Name                  string       `json:"name,omitempty"`
    SubGroups             []*SubGroups `json:"sub_groups,omitempty"`
    Usage                 *Usage       `json:"usage,omitempty"`
}
    LabelGroup represents a Label Group in the Illumio PCE

func GetAllLabelGroups(pce PCE, provisionStatus string) ([]LabelGroup, APIResponse, error)
    GetAllLabelGroups returns a slice of all Label Groups of a specific
    provision status in the Illumio PCE.

    The pvoision status must be "draft" or "active". The first call does not
    use the async option. If the response array length is >=500, it is
    re-run enabling async.

type OpenServicePorts struct {
    Address        string `json:"address,omitempty"`
    Package        string `json:"package,omitempty"`
    Port           int    `json:"port,omitempty"`
    ProcessName    string `json:"process_name,omitempty"`
    Protocol       int    `json:"protocol,omitempty"`
    User           string `json:"user,omitempty"`
    WinServiceName string `json:"win_service_name,omitempty"`
}
    OpenServicePorts represents open ports for a service running on a
    workload

type PCE struct {
    FQDN               string
    Port               int
    Org                int
    User               string
    Key                string
    DisableTLSChecking bool
}
    PCE represents an Illumio PCE and the necessary info to authenticate

type PairingKey struct {
    ActivationCode string `json:"activation_code,omitempty"`
}
    PairingKey represents a VEN pairing key

type PairingProfile struct {
    AllowedUsesPerKey     string     `json:"allowed_uses_per_key,omitempty"`
    AppLabelLock          bool       `json:"app_label_lock"`
    CreatedAt             string     `json:"created_at,omitempty"`
    CreatedBy             *CreatedBy `json:"created_by,omitempty"`
    Description           string     `json:"description,omitempty"`
    Enabled               bool       `json:"enabled"`
    EnvLabelLock          bool       `json:"env_label_lock"`
    ExternalDataReference string     `json:"external_data_reference,omitempty"`
    ExternalDataSet       string     `json:"external_data_set,omitempty"`
    Href                  string     `json:"href,omitempty,omitempty"`
    IsDefault             bool       `json:"is_default,omitempty"`
    KeyLifespan           string     `json:"key_lifespan,omitempty"`
    Labels                []*Label   `json:"labels,omitempty"`
    LastPairingAt         string     `json:"last_pairing_at,omitempty"`
    LocLabelLock          bool       `json:"loc_label_lock"`
    LogTraffic            bool       `json:"log_traffic"`
    LogTrafficLock        bool       `json:"log_traffic_lock"`
    Mode                  string     `json:"mode,omitempty"`
    ModeLock              bool       `json:"mode_lock"`
    Name                  string     `json:"name,omitempty"`
    RoleLabelLock         bool       `json:"role_label_lock"`
    TotalUseCount         int        `json:"total_use_count,omitempty"`
    UpdatedAt             string     `json:"updated_at,omitempty"`
    UpdatedBy             *UpdatedBy `json:"updated_by,omitempty,omitempty"`
    VisibilityLevel       string     `json:"visibility_level,omitempty"`
    VisibilityLevelLock   bool       `json:"visibility_level_lock"`
}
    PairingProfile represents a pairing profile in the Illumio PCE

func GetAllPairingProfiles(pce PCE) ([]PairingProfile, APIResponse, error)
    GetAllPairingProfiles gets all pairing profiles in the Illumio PCE.

type PortProtos struct {
    Include []Include `json:"include"`
    Exclude []Exclude `json:"exclude"`
}
    PortProtos represents the ports and protocols query portion of the
    exporer API

type ProductVersion struct {
    Build           int    `json:"build,omitempty"`
    EngineeringInfo string `json:"engineering_info,omitempty"`
    LongDisplay     string `json:"long_display,omitempty"`
    ReleaseInfo     string `json:"release_info,omitempty"`
    ShortDisplay    string `json:"short_display,omitempty"`
    Version         string `json:"version,omitempty"`
}
    ProductVersion represents the version of the product

type Providers struct {
    Actors        string         `json:"actors,omitempty"`
    BoundService  *BoundService  `json:"bound_service,omitempty"`
    IPList        *IPList        `json:"ip_list,omitempty"`
    Label         *Label         `json:"label,omitempty"`
    LabelGroup    *LabelGroup    `json:"label_group,omitempty"`
    VirtualServer *VirtualServer `json:"virtual_server,omitempty"`
    Workload      *Workload      `json:"workload,omitempty"`
}
    Providers represent providers in an Illumio ruleset

type Rules struct {
    Consumers                   []*Consumers                   `json:"consumers"`
    ConsumingSecurityPrincipals []*ConsumingSecurityPrincipals `json:"consuming_security_principals,omitempty"`
    Description                 string                         `json:"description,omitempty"`
    Enabled                     bool                           `json:"enabled"`
    ExternalDataReference       interface{}                    `json:"external_data_reference,omitempty"`
    ExternalDataSet             interface{}                    `json:"external_data_set,omitempty"`
    Href                        string                         `json:"href,omitempty"`
    Providers                   []*Providers                   `json:"providers"`
    SecConnect                  bool                           `json:"sec_connect,omitempty"`
    Service                     *Service                       `json:"service"`
    UnscopedConsumers           bool                           `json:"unscoped_consumers,omitempty"`
    UpdateType                  string                         `json:"update_type,omitempty"`
}
    Rules represent Illumio Rules

type Ruleset struct {
    CreatedAt             string           `json:"created_at"`
    CreatedBy             *CreatedBy       `json:"created_by,omitempty"`
    DeletedAt             string           `json:"deleted_at"`
    DeletedBy             *DeletedBy       `json:"deleted_by,omitempty"`
    Description           string           `json:"description"`
    Enabled               bool             `json:"enabled"`
    ExternalDataReference string           `json:"external_data_reference,omitempty"`
    ExternalDataSet       string           `json:"external_data_set,omitempty"`
    Href                  string           `json:"href,omitempty"`
    IPTablesRules         []*IPTablesRules `json:"ip_tables_rules,omitempty"`
    Name                  string           `json:"name"`
    Rules                 []*Rules         `json:"rules"`
    Scopes                [][]*Scopes      `json:"scopes"`
    UpdateType            string           `json:"update_type,omitempty"`
    UpdatedAt             string           `json:"updated_at"`
    UpdatedBy             *UpdatedBy       `json:"updated_by,omitempty"`
    PolicySecStatus       string
}
    Ruleset represents an Illumio RuleSet

func GetAllRuleSets(pce PCE, provisionStatus string) ([]Ruleset, APIResponse, error)
    GetAllRuleSets returns a slice of Rulesets for all RuleSets in the
    Illumio PCE

type Scopes struct {
    Label      *Label      `json:"label,omitempty"`
    LabelGroup *LabelGroup `json:"label_group,omitempty"`
}
    Scopes represent the scope of an Illumio Rule

type SecureConnect struct {
    MatchingIssuerName string `json:"matching_issuer_name,omitempty"`
}
    SecureConnect represents SecureConnect for an Agent on a Workload

type Service struct {
    CreatedAt             string            `json:"created_at,omitempty"`
    CreatedBy             *CreatedBy        `json:"created_by,omitempty"`
    DeletedAt             string            `json:"deleted_at,omitempty"`
    DeletedBy             *DeletedBy        `json:"deleted_by,omitempty"`
    Description           string            `json:"description,omitempty"`
    DescriptionURL        string            `json:"description_url,omitempty"`
    ExternalDataReference string            `json:"external_data_reference,omitempty"`
    ExternalDataSet       string            `json:"external_data_set,omitempty"`
    Href                  string            `json:"href,omitempty"`
    Name                  string            `json:"name"`
    ProcessName           string            `json:"process_name,omitempty"`
    ServicePorts          []*ServicePort    `json:"service_ports,omitempty"`
    UpdateType            string            `json:"update_type,omitempty"`
    UpdatedAt             string            `json:"updated_at,omitempty"`
    UpdatedBy             *UpdatedBy        `json:"updated_by,omitempty"`
    WindowsServices       []*WindowsService `json:"windows_services,omitempty"`
}
    Service represent a service in the Illumio PCE

func CreateService(pce PCE, service Service) (Service, APIResponse, error)
    CreateService creates a new service in the Illumio PCE

func GetAllServices(pce PCE, provisionStatus string) ([]Service, APIResponse, error)
    GetAllServices returns a slice of Services for each Service in the
    Illumio PCE. provisionStatus must either be "draft" or "active"

type ServicePort struct {
    IcmpCode int `json:"icmp_code,omitempty"`
    IcmpType int `json:"icmp_type,omitempty"`
    ID       int `json:"id,omitempty"`
    Port     int `json:"port,omitempty"`
    Protocol int `json:"protocol"`
    ToPort   int `json:"to_port,omitempty"`
}
    ServicePort represent port and protocol information for a non-Windows
    service

type Services struct {
    CreatedAt        string              `json:"created_at,omitempty"`
    OpenServicePorts []*OpenServicePorts `json:"open_service_ports,omitempty"`
    UptimeSeconds    int                 `json:"uptime_seconds,omitempty"`
}
    Services represent the Services running on a Workload

type Sources struct {
    Include [][]Include `json:"include"`
    Exclude []Exclude   `json:"exclude"`
}
    Sources represents the sources query portion of the explorer API

type Src struct {
    IP       string    `json:"ip"`
    Workload *Workload `json:"workload,omitempty"`
}
    Src Traffic flow endpoint details

type Statements struct {
    ChainName  string `json:"chain_name"`
    Parameters string `json:"parameters"`
    TableName  string `json:"table_name"`
}
    Statements represent statements

type Status struct {
    AgentHealth              []*AgentHealth     `json:"agent_health,omitempty"`
    AgentHealthErrors        *AgentHealthErrors `json:"agent_health_errors,omitempty"`
    AgentVersion             string             `json:"agent_version,omitempty"`
    FirewallRuleCount        int                `json:"firewall_rule_count,omitempty"`
    FwConfigCurrent          bool               `json:"fw_config_current,omitempty"`
    LastHeartbeatOn          string             `json:"last_heartbeat_on,omitempty"`
    ManagedSince             string             `json:"managed_since,omitempty"`
    SecurityPolicyAppliedAt  string             `json:"security_policy_applied_at,omitempty"`
    SecurityPolicyReceivedAt string             `json:"security_policy_received_at,omitempty"`
    SecurityPolicyRefreshAt  string             `json:"security_policy_refresh_at,omitempty"`
    SecurityPolicySyncState  string             `json:"security_policy_sync_state,omitempty"`
    UID                      string             `json:"uid,omitempty"`
    UptimeSeconds            int                `json:"uptime_seconds,omitempty"`
}
    Status represents the Status of an Agent on a Workload

type SubGroups struct {
    Href string `json:"href"`
    Name string `json:"name,omitempty"`
}
    SubGroups represent SubGroups for Label Groups

type TimestampRange struct {
    FirstDetected string `json:"first_detected"`
    LastDetected  string `json:"last_detected"`
}
    TimestampRange Timestamp ranges for the flow detected

type TrafficAnalysis struct {
    Dst            *Dst            `json:"dst"`
    NumConnections int             `json:"num_connections"`
    PolicyDecision string          `json:"policy_decision"`
    ExpSrv         *ExpSrv         `json:"service"`
    Src            *Src            `json:"src"`
    TimestampRange *TimestampRange `json:"timestamp_range"`
}
    TrafficAnalysis represents the response from the traffic analysis api

func GetTrafficAnalysis(pce PCE, query TrafficQuery) ([]TrafficAnalysis, error)
    GetTrafficAnalysis gets flow data from Explorer.

    sourcesInclude, sourcesExclude, destinationsInclude, destinationsExclude
    are array of strings that are hrefs for labels, hrefs for workloads, or
    values for ip_addresses.

    portProtoInclude and portProtoExclude are an array of arrays. For
    example, [[3306, 6], [8080,-1]] is Port 3306 TCP and Port 8080 any
    protocol.

    policyStatuses is an array that contains only the values allowed,
    potentially_blocked, and/or blocked.

type TrafficAnalysisRequest struct {
    Sources          Sources          `json:"sources"`
    Destinations     Destinations     `json:"destinations"`
    ExplorerServices ExplorerServices `json:"services"`
    StartDate        time.Time        `json:"start_date,omitempty"`
    EndDate          time.Time        `json:"end_date,omitempty"`
    PolicyDecisions  []string         `json:"policy_decisions"`
    MaxResults       int              `json:"max_results,omitempty"`
}
    TrafficAnalysisRequest represents the payload object for the traffic
    analysis POST request

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
    TrafficQuery is the struct to be passed to the GetTrafficAnalysis
    function

type UpdatedBy struct {
    Href string `json:"href"`
}
    UpdatedBy represents the UpdatedBy property of an object

type Usage struct {
    LabelGroup         bool `json:"label_group"`
    Rule               bool `json:"rule"`
    Ruleset            bool `json:"ruleset"`
    StaticPolicyScopes bool `json:"static_policy_scopes,omitempty"`
}
    Usage covers how a LabelGroup is used in the PCE

type UserLogin struct {
    AuthUsername                string          `json:"auth_username,omitempty"`
    FullName                    string          `json:"full_name,omitempty"`
    Href                        string          `json:"href,omitempty"`
    InactivityExpirationMinutes int             `json:"inactivity_expiration_minutes,omitempty"`
    LastLoginIPAddress          string          `json:"last_login_ip_address,omitempty"`
    LastLoginOn                 string          `json:"last_login_on,omitempty"`
    ProductVersion              *ProductVersion `json:"product_version,omitempty"`
    SessionToken                string          `json:"session_token,omitempty"`
    TimeZone                    string          `json:"time_zone,omitempty,omitempty"`
    Type                        string          `json:"type,omitempty"`
}
    UserLogin represents a user logging in via password to get a session key

func Login(pce PCE, authToken string) (UserLogin, APIResponse, error)
    Login takes an auth token and returns a session token

type VirtualServer struct {
    Href string `json:"href"`
}
    VirtualServer represent Virtual Servers

type WindowsService struct {
    IcmpCode    int    `json:"icmp_code,omitempty"`
    IcmpType    int    `json:"icmp_type,omitempty"`
    Port        int    `json:"port,omitempty"`
    ProcessName string `json:"process_name,omitempty"`
    Protocol    int    `json:"protocol,omitempty"`
    ServiceName string `json:"service_name,omitempty"`
    ToPort      int    `json:"to_port,omitempty"`
}
    WindowsService represents port and protocol information for a Windows
    service

type Workload struct {
    Agent                 *Agent       `json:"agent,omitempty"`
    CreatedAt             string       `json:"created_at,omitempty"`
    CreatedBy             *CreatedBy   `json:"created_by,omitempty"`
    DataCenter            string       `json:"data_center,omitempty"`
    DataCenterZone        string       `json:"data_center_zone,omitempty"`
    DeleteType            string       `json:"delete_type,omitempty"`
    Deleted               *bool        `json:"deleted,omitempty"`
    DeletedAt             string       `json:"deleted_at,omitempty"`
    DeletedBy             *DeletedBy   `json:"deleted_by,omitempty"`
    Description           string       `json:"description,omitempty"`
    ExternalDataReference string       `json:"external_data_reference,omitempty"`
    ExternalDataSet       string       `json:"external_data_set,omitempty"`
    Hostname              string       `json:"hostname,omitempty"`
    Href                  string       `json:"href,omitempty"`
    Interfaces            []*Interface `json:"interfaces,omitempty"`
    Labels                []*Label     `json:"labels,omitempty"`
    Name                  string       `json:"name,omitempty"`
    Online                bool         `json:"online,omitempty"`
    OsDetail              string       `json:"os_detail,omitempty"`
    OsID                  string       `json:"os_id,omitempty"`
    PublicIP              string       `json:"public_ip,omitempty"`
    ServicePrincipalName  string       `json:"service_principal_name,omitempty"`
    ServiceProvider       string       `json:"service_provider,omitempty"`
    Services              *Services    `json:"services,omitempty"`
    UpdatedAt             string       `json:"updated_at,omitempty"`
    UpdatedBy             *UpdatedBy   `json:"updated_by,omitempty"`
}
    A Workload is a Workload object in the PCE

func CreateWorkload(pce PCE, workload Workload) (Workload, APIResponse, error)
    CreateWorkload creates a new workload in the Illumio PCE

func GetAllWorkloads(pce PCE) ([]Workload, APIResponse, error)
    GetAllWorkloads returns an slice of workloads for each workload in the
    Illumio PCE

SUBDIRECTORIES

	illumioapi_test



```
