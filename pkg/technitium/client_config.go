package technitium

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// LogLevel represents the logging level
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// ClientConfig holds how the configurator connects and authenticates, and
// where it reads and writes files. Values come from defaults, then the
// optional client config file, then environment variables, then flags.
type ClientConfig struct {
	APIURL   string `yaml:"api_url" env:"DNS_API_URL"`
	APIToken string `yaml:"api_token" env:"DNS_API_TOKEN"`
	// APITokenFile holds the API token: the file create-token writes, or a
	// bare token. Read by LoadAPITokenFile, which sets APIToken.
	APITokenFile string `yaml:"api_token_file" env:"DNS_API_TOKEN_FILE"`
	Username     string `yaml:"username" env:"DNS_USERNAME"`
	Password     string `yaml:"password" env:"DNS_PASSWORD"`
	NewPassword  string `yaml:"new_password" env:"DNS_NEW_PASSWORD"`
	// ConfigPath is the DNS config file `configure` reads when no file
	// argument is given.
	ConfigPath string        `yaml:"config_path" env:"DNS_CONFIG_PATH"`
	TokenPath  string        `yaml:"token_path" env:"DNS_TOKEN_PATH"`
	Timeout    time.Duration `yaml:"timeout" env:"DNS_TIMEOUT"`
	// WaitTimeout bounds how long commands wait for /api/status to answer,
	// at start and after settings restart the web service. Zero disables
	// the wait.
	WaitTimeout time.Duration `yaml:"wait_timeout" env:"DNS_WAIT_TIMEOUT"`
	LogLevel    LogLevel      `yaml:"log_level" env:"DNS_LOG_LEVEL"`
	// Kubernetes Secret that create-token stores the token in. An empty
	// namespace means the current one, as kubectl would choose it.
	K8sSecretName      string `yaml:"k8s_secret_name" env:"DNS_K8S_SECRET_NAME"`
	K8sSecretNamespace string `yaml:"k8s_secret_namespace" env:"DNS_K8S_SECRET_NAMESPACE"`
	K8sSecretKey       string `yaml:"k8s_secret_key" env:"DNS_K8S_SECRET_KEY"`
}

// DefaultConfig returns a ClientConfig with default values.
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		ConfigPath:   "config.yaml",
		Timeout:      30 * time.Second,
		WaitTimeout:  60 * time.Second,
		LogLevel:     LogLevelInfo,
		K8sSecretKey: "api-token",
	}
}

// GetLogLevel returns the slog.Level for the configured LogLevel.
func (c *ClientConfig) GetLogLevel() slog.Level {
	switch strings.ToLower(string(c.LogLevel)) {
	case string(LogLevelDebug):
		return slog.LevelDebug
	case string(LogLevelWarn):
		return slog.LevelWarn
	case string(LogLevelError):
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// LoadFromFile reads a client config file. The file must exist, since it
// is only loaded when a path is given, and unknown keys are errors.
func (c *ClientConfig) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read client config file: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse client config file %s: %w", path, err)
	}
	// KnownFields checks only the document decoded, so a second one would
	// be ignored unchecked.
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse client config file %s: it must hold a single YAML document", path)
	}
	return nil
}

// LoadFromEnv overrides values from environment variables that are set.
func (c *ClientConfig) LoadFromEnv() error {
	val := reflect.ValueOf(c).Elem()
	typ := val.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		envTag := field.Tag.Get("env")
		if envTag == "" {
			continue
		}
		envVal := os.Getenv(envTag)
		if envVal == "" {
			continue
		}
		if field.Type == reflect.TypeOf(time.Duration(0)) {
			duration, err := time.ParseDuration(envVal)
			if err != nil {
				return fmt.Errorf("invalid %s value: %w", envTag, err)
			}
			val.Field(i).Set(reflect.ValueOf(duration))
			continue
		}
		val.Field(i).SetString(envVal)
	}
	return nil
}

// commandsNeedingAPIAuth authenticate with a token or a username and password.
var commandsNeedingAPIAuth = map[string]bool{
	"configure":     true,
	"cluster-state": true,
	"export":        true,
}

// Validate checks that the configuration has what the command needs.
func (c *ClientConfig) Validate(command string) error {
	if c.APIURL == "" {
		return errors.New("API URL is required (set DNS_API_URL or api_url)")
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be greater than 0")
	}
	if c.WaitTimeout < 0 {
		return errors.New("wait timeout must not be negative")
	}
	switch strings.ToLower(string(c.LogLevel)) {
	case "", string(LogLevelDebug), string(LogLevelInfo), string(LogLevelWarn), string(LogLevelError):
	default:
		return fmt.Errorf("log level %q must be debug, info, warn or error", c.LogLevel)
	}

	if c.APIToken != "" && c.APITokenFile != "" {
		return errors.New("set an API token (DNS_API_TOKEN) or an API token file (DNS_API_TOKEN_FILE), not both")
	}
	if commandsNeedingAPIAuth[command] && c.APIToken == "" && c.APITokenFile == "" && (c.Username == "" || c.Password == "") {
		return fmt.Errorf("%s needs an API token (DNS_API_TOKEN or DNS_API_TOKEN_FILE) or a username and password (DNS_USERNAME, DNS_PASSWORD)", command)
	}

	switch command {
	case "create-token", "change-password":
		if c.Username == "" || c.Password == "" {
			return errors.New("username and password are required (set DNS_USERNAME and DNS_PASSWORD)")
		}
		if command == "change-password" && c.NewPassword == "" {
			return errors.New("new password is required (set DNS_NEW_PASSWORD)")
		}
		if command == "create-token" && c.TokenPath == "" && c.K8sSecretName == "" {
			return errors.New("a token destination is required (set DNS_TOKEN_PATH and/or DNS_K8S_SECRET_NAME)")
		}
	}
	return nil
}

// LoadAPITokenFile sets APIToken from APITokenFile for the commands that
// authenticate with a token. The other commands leave the file unread, so a
// client config shared with create-token can name a file it has yet to write.
func (c *ClientConfig) LoadAPITokenFile(command string) error {
	if c.APITokenFile == "" || !commandsNeedingAPIAuth[command] {
		return nil
	}
	data, err := os.ReadFile(c.APITokenFile)
	if err != nil {
		return fmt.Errorf("read API token file: %w", err)
	}
	token, err := ParseTokenFile(data)
	if err != nil {
		return fmt.Errorf("read API token file %s: %w", c.APITokenFile, err)
	}
	if token == "" {
		return fmt.Errorf("API token file %s holds no token", c.APITokenFile)
	}
	c.APIToken = token
	return nil
}
