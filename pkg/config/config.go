package config

import (
	"fmt"
	"os"
	"reflect"

	"github.com/ashtonian/technitium-sdk-go/pkg/technitium"
	"gopkg.in/yaml.v3"
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
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	NewPassword string `yaml:"newPassword"` // Only used for change-password command
}

// TokenConfig represents the token configuration
type TokenConfig struct {
	Token string `yaml:"token"`
}

// ClientConfig represents the client configuration structure
type ClientConfig struct {
	// Server configuration
	APIURL string `yaml:"api_url" env:"DNS_API_URL"`

	// Authentication configuration
	APIToken string `yaml:"api_token" env:"DNS_API_TOKEN"`
	Username string `yaml:"username" env:"DNS_USERNAME"`
	Password string `yaml:"password" env:"DNS_PASSWORD"`

	// Command-specific configuration
	NewPassword string `yaml:"new_password" env:"DNS_NEW_PASSWORD"`

	// File paths
	ConfigPath      string `yaml:"-"` // Not stored in YAML, set via flag
	CredentialsPath string `yaml:"credentials_path" env:"DNS_CREDENTIALS_PATH"`
	TokenPath       string `yaml:"token_path" env:"DNS_TOKEN_PATH"`
}

// DefaultConfig returns a ClientConfig with default values
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		ConfigPath:      "config.yaml",
		CredentialsPath: "credentials.yaml",
		TokenPath:       "token.yaml",
	}
}

// LoadFromFile loads configuration from a YAML file
func (c *ClientConfig) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist is not an error
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, c); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

// LoadFromEnv overrides configuration values from environment variables
func (c *ClientConfig) LoadFromEnv() error {
	val := reflect.ValueOf(c).Elem()
	typ := val.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		envTag := field.Tag.Get("env")
		if envTag == "" {
			continue
		}

		if envVal := os.Getenv(envTag); envVal != "" {
			val.Field(i).SetString(envVal)
		}
	}

	return nil
}

// Validate checks if the configuration is valid for the given command
func (c *ClientConfig) Validate(command string) error {
	if c.APIURL == "" {
		return fmt.Errorf("API URL is required (set DNS_API_URL or api_url in config)")
	}

	switch command {
	case "configure":
		if c.APIToken == "" && (c.Username == "" || c.Password == "") {
			return fmt.Errorf("either API token (DNS_API_TOKEN) or username/password (DNS_USERNAME/DNS_PASSWORD) is required for configure command")
		}
	case "create-token", "change-password":
		if c.Username == "" || c.Password == "" {
			return fmt.Errorf("username and password are required (set DNS_USERNAME/DNS_PASSWORD or username/password in config)")
		}
		if command == "change-password" && c.NewPassword == "" {
			return fmt.Errorf("new password is required (set DNS_NEW_PASSWORD or new_password in config)")
		}
	}

	return nil
}
