package technitium

import (
	"context"
	"encoding/json"
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
	ID        int              `json:"id"`
	Name      string           `json:"name"`
	URL       string           `json:"url"`
	IPAddress string           `json:"ipAddress"`
	Type      ClusterNodeType  `json:"type"`
	State     ClusterNodeState `json:"state"`
	LastSeen  string           `json:"lastSeen"`
}

// ClusterState represents the current state of the Technitium DNS cluster
type ClusterState struct {
	ClusterInitialized         bool          `json:"clusterInitialized"`
	DnsServerDomain            string        `json:"dnsServerDomain"`
	Version                    string        `json:"version"`
	ClusterDomain              string        `json:"clusterDomain"`
	HeartbeatRefreshIntervalSecs int         `json:"heartbeatRefreshIntervalSeconds"`
	HeartbeatRetryIntervalSecs   int         `json:"heartbeatRetryIntervalSeconds"`
	ConfigRefreshIntervalSecs    int         `json:"configRefreshIntervalSeconds"`
	ConfigRetryIntervalSecs      int         `json:"configRetryIntervalSeconds"`
	ConfigLastSynced           string        `json:"configLastSynced"`
	Nodes                      []ClusterNode `json:"nodes"`
	ServerIpAddresses          []string      `json:"serverIpAddresses"`
}

// ClusterJoinRequest contains the parameters for joining a cluster
type ClusterJoinRequest struct {
	SecondaryNodeIPs    string `url:"secondaryNodeIpAddresses"`
	PrimaryNodeURL      string `url:"primaryNodeUrl"`
	PrimaryNodeIP       string `url:"primaryNodeIpAddress,omitempty"`
	PrimaryNodeUsername string `url:"primaryNodeUsername"`
	PrimaryNodePassword string `url:"primaryNodePassword"`
	IgnoreCertErrors    bool   `url:"ignoreCertificateErrors,omitempty"`
}

// GetClusterState retrieves the current cluster state from the Technitium DNS server
func (c *Client) GetClusterState(ctx context.Context) (*ClusterState, error) {
	params := struct {
		IncludeServerIpAddresses bool `url:"includeServerIpAddresses"`
	}{
		IncludeServerIpAddresses: true,
	}

	resp, err := c.callGET(ctx, "/api/admin/cluster/state", params)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster state: %w", err)
	}

	var state ClusterState
	if err := json.Unmarshal(resp.Response, &state); err != nil {
		return nil, fmt.Errorf("failed to parse cluster state: %w", err)
	}

	return &state, nil
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

	resp, err := c.callGET(ctx, "/api/admin/cluster/init", params)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize cluster: %w", err)
	}

	var state ClusterState
	if err := json.Unmarshal(resp.Response, &state); err != nil {
		return nil, fmt.Errorf("failed to parse cluster init response: %w", err)
	}

	return &state, nil
}

// ClusterJoin joins a secondary node to an existing cluster
func (c *Client) ClusterJoin(ctx context.Context, req ClusterJoinRequest) (*ClusterState, error) {
	resp, err := c.callPOSTForm(ctx, "/api/admin/cluster/initJoin", req)
	if err != nil {
		return nil, fmt.Errorf("failed to join cluster: %w", err)
	}

	var state ClusterState
	if err := json.Unmarshal(resp.Response, &state); err != nil {
		return nil, fmt.Errorf("failed to parse cluster join response: %w", err)
	}

	return &state, nil
}
