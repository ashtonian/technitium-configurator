package technitium

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveNodeIPs(t *testing.T) {
	for _, tt := range []struct {
		name       string
		configured string
		reported   []string
		want       []string
		failure    string
	}{
		{"literal addresses remain authoritative", "192.0.2.10,192.0.2.11", []string{"198.51.100.20"}, []string{"192.0.2.10", "192.0.2.11"}, ""},
		{"target interfaces", "auto", []string{"192.0.2.11", "::ffff:192.0.2.10", "192.0.2.10", "2001:db8::1"}, []string{"192.0.2.10", "192.0.2.11", "2001:db8::1"}, ""},
		{"stable address with target interfaces", "192.0.2.50,auto,192.0.2.10", []string{"192.0.2.10"}, []string{"192.0.2.10", "192.0.2.50"}, ""},
		{"discovery cannot silently fall back to the stable address", "auto,192.0.2.50", nil, nil, "no usable interface addresses"},
		{"empty discovery", "auto", nil, nil, "no usable interface addresses"},
		{"invalid discovery", "auto", []string{"192.0.2.10", "invalid"}, nil, "unusable address"},
		{"loopback", "auto", []string{"127.0.0.1"}, nil, "unusable address"},
		{"link local", "auto", []string{"fe80::1%eth0"}, nil, "unusable address"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cc := &ClusterConfig{NodeIPs: tt.configured}
			got, err := cc.ResolveNodeIPs(&ClusterState{ServerIpAddresses: tt.reported})
			if tt.failure != "" {
				require.ErrorContains(t, err, tt.failure)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAutomaticClusterConfig(t *testing.T) {
	_, err := load("cluster:\n  mode: primary\n  domain: cluster.example.test\n  nodeIPs: auto,192.0.2.50\n")
	require.NoError(t, err)
}
