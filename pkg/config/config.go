package config

import (
	"github.com/ashtonian/technitium-sdk-go/pkg/technitium"
)

// Config represents the root configuration structure
type Config struct {
	DNSSettings technitium.DnsSettings `yaml:"dnsSettings"`
	Zones       []ZoneConfig           `yaml:"zones"`
	Records     []RecordConfig         `yaml:"records"`
	Apps        []technitium.AppConfig `yaml:"apps"`
}

// ZoneConfig represents a zone configuration
type ZoneConfig struct {
	technitium.ZoneCreateRequest `yaml:",inline"`
	ACLSettings                  *technitium.ACLSettings `yaml:"aclSettings,omitempty"`
}

// RecordConfig represents a DNS record configuration
type RecordConfig struct {
	technitium.AddRecordRequest `yaml:",inline"`
}

// Credentials represents the credentials configuration
type Credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// TokenConfig represents the token configuration
type TokenConfig struct {
	Token string `yaml:"token"`
}
