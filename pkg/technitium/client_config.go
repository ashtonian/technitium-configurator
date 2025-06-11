package technitium

import (
	"fmt"
	"os"
	"reflect"
	"time"

	"gopkg.in/yaml.v3"
)

// ClientConfig represents the client configuration structure
type ClientConfig struct {
	APIURL      string        `yaml:"api_url" env:"DNS_API_URL"`
	APIToken    string        `yaml:"api_token" env:"DNS_API_TOKEN"`
	Username    string        `yaml:"username" env:"DNS_USERNAME"`
	Password    string        `yaml:"password" env:"DNS_PASSWORD"`
	NewPassword string        `yaml:"new_password" env:"DNS_NEW_PASSWORD"`
	ConfigPath  string        `yaml:"-" env:"DNS_CONFIG_PATH"` // Not stored in YAML, set via flag or env
	TokenPath   string        `yaml:"token_path" env:"DNS_TOKEN_PATH"`
	Timeout     time.Duration `yaml:"timeout" env:"DNS_TIMEOUT"`
}

// DefaultConfig returns a new ClientConfig with default values
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		ConfigPath: "config.yaml", // Default config file path
		TokenPath:  "token.yaml",  // Default token file path
		Timeout:    30 * time.Second,
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
			// Special handling for timeout
			if field.Type == reflect.TypeOf(time.Duration(0)) {
				duration, err := time.ParseDuration(envVal)
				if err != nil {
					return fmt.Errorf("invalid timeout value: %w", err)
				}
				val.Field(i).Set(reflect.ValueOf(duration))
			} else {
				// Special handling for ConfigPath - only set if not already set by flag
				if field.Name == "ConfigPath" && c.ConfigPath != "" && c.ConfigPath != "config.yaml" {
					continue // Skip if already set by flag
				}
				val.Field(i).SetString(envVal)
			}
		}
	}

	return nil
}

// Validate checks if the configuration is valid for the given command
func (c *ClientConfig) Validate(command string) error {
	if c.APIURL == "" {
		return fmt.Errorf("API URL is required (set DNS_API_URL or api_url in config)")
	}

	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
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
