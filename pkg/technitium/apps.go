package technitium

import (
	"context"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// AppConfig represents a generic app configuration that can be unmarshaled into specific types
type AppConfig struct {
	Name   string    `yaml:"name" url:"name"`
	Url    string    `yaml:"url" url:"url"`
	Config yaml.Node `yaml:"config,omitempty" url:"config,omitempty"`
}

func (a *AppConfig) GetConfigJSON() (string, error) {
	// if a.Config == nil {
	// 	return "", nil
	// }

	var cfg any
	switch a.Name {
	case "Advanced Blocking":
		cfg = new(BlockingConfig)
	case "Advanced Forwarding":
		cfg = new(ForwardingConfig)
	default:
		return "", fmt.Errorf("unknown app config type: %s", a.Name)
	}

	if err := a.Config.Decode(cfg); err != nil {
		return "", fmt.Errorf("decode app config %q: %w", a.Name, err)
	}

	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal app config %q: %w", a.Name, err)
	}

	return string(b), nil
}

type AppInstallRequest struct {
	Name string `url:"name"`
	Url  string `url:"url"`
}

// InstallApp installs a DNS app.
func (c *Client) InstallApp(ctx context.Context, app AppInstallRequest) error {
	_, err := c.callPOSTForm(ctx, "/api/apps/downloadAndInstall", app)
	if err != nil {
		return fmt.Errorf("install app %q: %w", app.Name, err)
	}
	return nil
}

type AppConfigResponse struct {
	Response string `json:"response"`
	Status   string `json:"status"`
}

type AppConfigRequest struct {
	Name   string `url:"name"`
	Config string `url:"config"`
}

// SetAppConfig sets the configuration for a DNS app.
func (c *Client) SetAppConfig(ctx context.Context, req AppConfigRequest) (*AppConfigResponse, error) {
	resp, err := c.callPOSTForm(ctx, "/api/apps/config/set", req)
	if err != nil {
		return nil, fmt.Errorf("set app config %q: %w", req.Name, err)
	}

	return &AppConfigResponse{
		Response: string(resp.Response),
		Status:   resp.Status,
	}, nil
}
