package technitium

import (
	"context"
	"fmt"
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
	ID          int              `json:"id"`
	Name        string           `json:"name"`
	URL         string           `json:"url"`
	IPAddresses []string         `json:"ipAddresses"`
	Type        ClusterNodeType  `json:"type"`
	State       ClusterNodeState `json:"state"`
	LastSeen    string           `json:"lastSeen"`
	UpSince     string           `json:"upSince"`
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
	ConfigLastSynced             string        `json:"configLastSynced"`
	Nodes                        []ClusterNode `json:"clusterNodes"`
	ServerIpAddresses            []string      `json:"serverIpAddresses"`
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
	HeartbeatRefreshIntervalSecs int `url:"heartbeatRefreshIntervalSeconds,omitempty"`
	HeartbeatRetryIntervalSecs   int `url:"heartbeatRetryIntervalSeconds,omitempty"`
	ConfigRefreshIntervalSecs    int `url:"configRefreshIntervalSeconds,omitempty"`
	ConfigRetryIntervalSecs      int `url:"configRetryIntervalSeconds,omitempty"`
}

// IsEmpty returns true when no timing options have been set.
func (r ClusterOptionsRequest) IsEmpty() bool {
	return r == (ClusterOptionsRequest{})
}

// GetClusterState retrieves the current cluster state from the Technitium DNS server
func (c *Client) GetClusterState(ctx context.Context) (*ClusterState, error) {
	params := struct {
		IncludeServerIpAddresses bool `url:"includeServerIpAddresses"`
	}{
		IncludeServerIpAddresses: true,
	}

	r, err := c.callGET(ctx, "/api/admin/cluster/state", params)
	if err != nil {
		return nil, fmt.Errorf("get cluster state: %w", err)
	}
	return unmarshalResp[ClusterState](r)
}

// ClusterInit initializes clustering on the primary node.
// Despite being a state mutation, Technitium uses GET for this endpoint.
func (c *Client) ClusterInit(ctx context.Context, clusterDomain, primaryNodeIPs string) (*ClusterState, error) {
	params := struct {
		ClusterDomain          string `url:"clusterDomain"`
		PrimaryNodeIPAddresses string `url:"primaryNodeIpAddresses"`
	}{
		ClusterDomain:          clusterDomain,
		PrimaryNodeIPAddresses: primaryNodeIPs,
	}

	r, err := c.callGET(ctx, "/api/admin/cluster/init", params)
	if err != nil {
		return nil, fmt.Errorf("initialize cluster: %w", err)
	}
	return unmarshalResp[ClusterState](r)
}

// ClusterJoin joins a secondary node to an existing cluster
func (c *Client) ClusterJoin(ctx context.Context, req ClusterJoinRequest) (*ClusterState, error) {
	r, err := c.callPOSTForm(ctx, "/api/admin/cluster/initJoin", req)
	if err != nil {
		return nil, fmt.Errorf("join cluster: %w", err)
	}
	return unmarshalResp[ClusterState](r)
}

// SetClusterOptions configures timing options on the cluster primary node.
// Despite being a state mutation, Technitium uses GET for this endpoint.
func (c *Client) SetClusterOptions(ctx context.Context, req ClusterOptionsRequest) error {
	_, err := c.callGET(ctx, "/api/admin/cluster/primary/setOptions", req)
	if err != nil {
		return fmt.Errorf("failed to set cluster options: %w", err)
	}
	return nil
}
