package technitium

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ClusterNodeType represents the type of a cluster node
type ClusterNodeType string

const (
	ClusterNodeTypePrimary   ClusterNodeType = "Primary"
	ClusterNodeTypeSecondary ClusterNodeType = "Secondary"
)

// ClusterNodeState represents the connectivity state of a cluster node
type ClusterNodeState string

const (
	ClusterNodeStateSelf        ClusterNodeState = "Self"
	ClusterNodeStateConnected   ClusterNodeState = "Connected"
	ClusterNodeStateUnreachable ClusterNodeState = "Unreachable"
)

// ClusterNode represents a single node in the Technitium DNS cluster
type ClusterNode struct {
	ID               int64            `json:"id"`
	Name             string           `json:"name"`
	URL              string           `json:"url"`
	IPAddresses      []string         `json:"ipAddresses"`
	Type             ClusterNodeType  `json:"type"`
	State            ClusterNodeState `json:"state"`
	Version          string           `json:"version"`
	LastSeen         string           `json:"lastSeen"`
	UpSince          string           `json:"upSince"`
	ConfigLastSynced string           `json:"configLastSynced"`
}

// ClusterState represents the current state of the Technitium DNS cluster
type ClusterState struct {
	ClusterInitialized           bool          `json:"clusterInitialized"`
	DnsServerDomain              string        `json:"dnsServerDomain"`
	Version                      string        `json:"version"`
	ClusterDomain                string        `json:"clusterDomain"`
	HeartbeatRefreshIntervalSecs int           `json:"heartbeatRefreshIntervalSeconds"`
	HeartbeatRetryIntervalSecs   int           `json:"heartbeatRetryIntervalSeconds"`
	ConfigRefreshIntervalSecs    int           `json:"configRefreshIntervalSeconds"`
	ConfigRetryIntervalSecs      int           `json:"configRetryIntervalSeconds"`
	Nodes                        []ClusterNode `json:"clusterNodes"`
	ServerIpAddresses            []string      `json:"serverIpAddresses"`
}

// Self returns this server's own node entry, if the cluster lists one.
func (s *ClusterState) Self() (ClusterNode, bool) {
	for _, n := range s.Nodes {
		if n.State == ClusterNodeStateSelf {
			return n, true
		}
	}
	return ClusterNode{}, false
}

// CatalogZone returns the name of the catalog zone the cluster replicates
// member zones through. Technitium names it in ClusterManager.cs.
func (s *ClusterState) CatalogZone() string {
	return "cluster-catalog." + s.ClusterDomain
}

// ClusterJoinRequest contains the parameters for joining a cluster
type ClusterJoinRequest struct {
	SecondaryNodeIPs    string `json:"secondaryNodeIpAddresses"`
	PrimaryNodeURL      string `json:"primaryNodeUrl"`
	PrimaryNodeIP       string `json:"primaryNodeIpAddress,omitempty"`
	PrimaryNodeUsername string `json:"primaryNodeUsername"`
	PrimaryNodePassword string `json:"primaryNodePassword"`
	PrimaryNodeTotp     string `json:"primaryNodeTotp,omitempty"`
	IgnoreCertErrors    bool   `json:"ignoreCertificateErrors,omitempty"`
}

// ClusterOptionsRequest contains timing parameters for the cluster primary node
type ClusterOptionsRequest struct {
	HeartbeatRefreshIntervalSecs int
	HeartbeatRetryIntervalSecs   int
	ConfigRefreshIntervalSecs    int
	ConfigRetryIntervalSecs      int
}

// DefaultClusterOptions are a new cluster's timing options
// (ClusterManager's constants).
var DefaultClusterOptions = ClusterOptionsRequest{
	HeartbeatRefreshIntervalSecs: 30,
	HeartbeatRetryIntervalSecs:   10,
	ConfigRefreshIntervalSecs:    900,
	ConfigRetryIntervalSecs:      60,
}

// Options returns the cluster's current timing options.
func (s *ClusterState) Options() ClusterOptionsRequest {
	return ClusterOptionsRequest{
		HeartbeatRefreshIntervalSecs: s.HeartbeatRefreshIntervalSecs,
		HeartbeatRetryIntervalSecs:   s.HeartbeatRetryIntervalSecs,
		ConfigRefreshIntervalSecs:    s.ConfigRefreshIntervalSecs,
		ConfigRetryIntervalSecs:      s.ConfigRetryIntervalSecs,
	}
}

// Merge returns r with the options it leaves out taken from current, as the
// server fills them.
func (r ClusterOptionsRequest) Merge(current ClusterOptionsRequest) ClusterOptionsRequest {
	pick := func(n, cur int) int {
		if n != 0 {
			return n
		}
		return cur
	}
	return ClusterOptionsRequest{
		HeartbeatRefreshIntervalSecs: pick(r.HeartbeatRefreshIntervalSecs, current.HeartbeatRefreshIntervalSecs),
		HeartbeatRetryIntervalSecs:   pick(r.HeartbeatRetryIntervalSecs, current.HeartbeatRetryIntervalSecs),
		ConfigRefreshIntervalSecs:    pick(r.ConfigRefreshIntervalSecs, current.ConfigRefreshIntervalSecs),
		ConfigRetryIntervalSecs:      pick(r.ConfigRetryIntervalSecs, current.ConfigRetryIntervalSecs),
	}
}

// Check applies the rule the server enforces across options.
func (r ClusterOptionsRequest) Check() error {
	if r.ConfigRefreshIntervalSecs <= r.HeartbeatRefreshIntervalSecs {
		return fmt.Errorf("configRefreshIntervalSeconds %d must be greater than heartbeatRefreshIntervalSeconds %d",
			r.ConfigRefreshIntervalSecs, r.HeartbeatRefreshIntervalSecs)
	}
	return nil
}

// IsEmpty returns true when no timing options have been set.
func (r ClusterOptionsRequest) IsEmpty() bool {
	return r == (ClusterOptionsRequest{})
}

func (r ClusterOptionsRequest) values() url.Values {
	v := url.Values{}
	set := func(key string, n int) {
		if n > 0 {
			v.Set(key, strconv.Itoa(n))
		}
	}
	set("heartbeatRefreshIntervalSeconds", r.HeartbeatRefreshIntervalSecs)
	set("heartbeatRetryIntervalSeconds", r.HeartbeatRetryIntervalSecs)
	set("configRefreshIntervalSeconds", r.ConfigRefreshIntervalSecs)
	set("configRetryIntervalSeconds", r.ConfigRetryIntervalSecs)
	return v
}

// GetClusterState retrieves the current cluster state from the Technitium DNS server
func (c *Client) GetClusterState(ctx context.Context) (*ClusterState, error) {
	const path = "/api/admin/cluster/state"
	raw, err := c.get(ctx, path, url.Values{"includeServerIpAddresses": {"true"}})
	if err != nil {
		return nil, fmt.Errorf("get cluster state: %w", err)
	}
	return decodeResponse[ClusterState](path, raw)
}

// ClusterInit initializes clustering on the primary node.
func (c *Client) ClusterInit(ctx context.Context, clusterDomain, primaryNodeIPs string) (*ClusterState, error) {
	const path = "/api/admin/cluster/init"
	raw, err := c.postForm(ctx, path, url.Values{
		"clusterDomain":          {clusterDomain},
		"primaryNodeIpAddresses": {primaryNodeIPs},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize cluster: %w", err)
	}
	return decodeResponse[ClusterState](path, raw)
}

// ClusterJoin joins a secondary node to an existing cluster
func (c *Client) ClusterJoin(ctx context.Context, req ClusterJoinRequest) (*ClusterState, error) {
	const path = "/api/admin/cluster/initJoin"
	form, err := jsonToFormValues(req)
	if err != nil {
		return nil, fmt.Errorf("join cluster: %w", err)
	}
	raw, err := c.postForm(ctx, path, form)
	if err != nil {
		return nil, fmt.Errorf("join cluster: %w", err)
	}
	return decodeResponse[ClusterState](path, raw)
}

// UpdateNodeIPAddresses replaces this node's cluster IP addresses.
func (c *Client) UpdateNodeIPAddresses(ctx context.Context, ips []string) error {
	if _, err := c.postForm(ctx, "/api/admin/cluster/updateIpAddress", url.Values{"ipAddresses": {strings.Join(ips, ",")}}); err != nil {
		return fmt.Errorf("update cluster node IP addresses: %w", err)
	}
	return nil
}

// SetClusterOptions configures timing options on the cluster primary node.
// It is idempotent, so it is safe to call on every run.
func (c *Client) SetClusterOptions(ctx context.Context, req ClusterOptionsRequest) error {
	if _, err := c.postForm(ctx, "/api/admin/cluster/primary/setOptions", req.values()); err != nil {
		return fmt.Errorf("set cluster options: %w", err)
	}
	return nil
}

// InClusterDomain reports whether serverDomain lies below clusterDomain.
// Cluster init renames every node into the cluster domain, and the server
// rejects a dnsServerDomain outside it afterwards.
func InClusterDomain(serverDomain, clusterDomain string) bool {
	d, c := CanonicalName(serverDomain), CanonicalName(clusterDomain)
	return d != c && InZone(d, c)
}
