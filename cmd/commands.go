package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ashtonian/technitium-sdk-go/pkg/kube"
	"github.com/ashtonian/technitium-sdk-go/pkg/technitium"
	"gopkg.in/yaml.v3"
)

// Command represents a command that can be executed
type Command struct {
	Name        string
	Description string
	Run         func(ctx context.Context, cfg *technitium.ClientConfig, args []string) error
}

// Commands is a map of all available commands
var Commands = map[string]Command{
	"configure": {
		Name:        "configure",
		Description: "Configure DNS server using the provided config file",
		Run:         runConfigure,
	},
	"create-token": {
		Name:        "create-token",
		Description: "Create an API token and save it to token.yaml",
		Run:         runCreateToken,
	},
	"change-password": {
		Name:        "change-password",
		Description: "Change the password for the current user",
		Run:         runChangePassword,
	},
}

// RunCommand executes the specified command with the given configuration
func RunCommand(ctx context.Context, cfg *technitium.ClientConfig, command string, args []string) error {
	cmd, ok := Commands[command]
	if !ok {
		return fmt.Errorf("unknown command: %s", command)
	}

	// Validate configuration for the command
	if err := cfg.Validate(command); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return cmd.Run(ctx, cfg, args)
}

func runConfigure(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client := technitium.NewClient(cfg)

	cfgPath := cfg.ConfigPath
	if len(args) > 0 {
		cfgPath = args[0]
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var dnsCfg technitium.Config
	if err := yaml.Unmarshal(data, &dnsCfg); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Apply DNS settings
	if err := client.SetDNSSettings(ctx, dnsCfg.DNSSettings); err != nil {
		return fmt.Errorf("failed to set DNS settings: %w", err)
	}
	slog.Info("DNS settings configured")

	// Configure zones
	for _, z := range dnsCfg.Zones {
		zoneReq := technitium.ZoneCreateRequest{
			Zone:                       z.Zone,
			Type:                       z.Type,
			PrimaryNameServerAddresses: z.PrimaryNameServerAddresses,
			ZoneTransferProtocol:       z.ZoneTransferProtocol,
			TsigKeyName:                z.TsigKeyName,
			ValidateZone:               z.ValidateZone,
			Protocol:                   z.Protocol,
			Forwarder:                  z.Forwarder,
			DnssecValidation:           z.DnssecValidation,
			ProxyType:                  z.ProxyType,
			ProxyAddress:               z.ProxyAddress,
			ProxyPort:                  z.ProxyPort,
			ProxyUsername:              z.ProxyUsername,
			ProxyPassword:              z.ProxyPassword,
			Catalog:                    z.Catalog,
			UseSoaSerialDateScheme:     z.UseSoaSerialDateScheme,
			InitializeForwarder:        z.InitializeForwarder,
		}

		if _, err := client.CreateZone(ctx, zoneReq); err != nil {
			slog.Error("Failed to create zone", "zone", z.Zone, "error", err)
			err = nil // continue to update options
		}

		opts := technitium.ZoneOptionsUpdate{
			Zone:                       z.Zone,
			Catalog:                    z.Catalog,
			PrimaryNameServerAddresses: z.PrimaryNameServerAddresses,
			PrimaryXfrProto:            z.ZoneTransferProtocol,
			PrimaryXfrTsigKey:          z.TsigKeyName,
			ValidateZone:               z.ValidateZone,
		}

		if z.ACLSettings != nil {
			opts.ACLSettings = *z.ACLSettings
		}

		// api doesn't like immediate updates to zone sometimes..
		time.Sleep(1 * time.Second)

		if _, err := client.SetZoneOptions(ctx, opts); err != nil {
			slog.Error("Failed to update zone options", "zone", z.Zone, "error", err)
		} else {
			slog.Info("Zone configured", "zone", z.Zone)
		}
	}

	// Configure records
	for _, r := range dnsCfg.Records {
		if _, err := client.AddRecord(ctx, r); err != nil {
			slog.Error("Failed to add record", "domain", r.Domain, "error", err)
		} else {
			slog.Info("Record configured", "domain", r.Domain)
		}
	}

	// Install and configure apps
	for _, app := range dnsCfg.Apps {
		slog.Info("Installing app", "app", app.Name)

		// Install the app
		req := technitium.AppInstallRequest{
			Name: app.Name,
			Url:  app.Url,
		}
		err = client.InstallApp(ctx, req)
		if err != nil {
			slog.Error("Failed to install app", "error", err, "app", app.Name)
			err = nil // continue to config
		}

		slog.Info("Configuring app", "app", app.Name)
		config, err := app.GetConfigJSON()
		if err != nil {
			slog.Error("Failed to get app config", "error", err, "app", app.Name)
			continue
		}

		reqConfig := technitium.AppConfigRequest{
			Name:   app.Name,
			Config: config,
		}

		_, err = client.SetAppConfig(ctx, reqConfig)
		if err != nil {
			slog.Error("Failed to set app config", "error", err, "app", app.Name)
		}
		slog.Info("App configured", "app", app.Name)
	}

	slog.Info("Configuration complete!")
	return nil
}

func runCreateToken(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client := technitium.NewClient(cfg)

	// Check for existing token in Kubernetes secret if configured
	if cfg.K8sSecretName != "" {
		k8s, err := kube.NewK8sClient()
		if err != nil {
			return fmt.Errorf("failed to create k8s client: %w", err)
		}

		existingToken, err := k8s.CheckSecretToken(ctx, cfg.K8sSecretNamespace, cfg.K8sSecretName, cfg.K8sSecretKey)
		if err != nil {
			slog.Warn("Failed to check k8s secret", "error", err, "secret", cfg.K8sSecretName)
		} else if existingToken != "" {
			slog.Warn("to	ken already exists in k8s secret", "secret", fmt.Sprintf("%s/%s", cfg.K8sSecretNamespace, cfg.K8sSecretName))
			return nil
		}
	}

	// Check for existing token in file if configured
	if cfg.TokenPath != "" {
		var existingToken technitium.CreateTokenResponse
		if _, err := os.Stat(cfg.TokenPath); err == nil {
			data, err := os.ReadFile(cfg.TokenPath)
			if err != nil {
				return fmt.Errorf("failed to read token file: %w", err)
			}
			// TODO: hack unmarshal model
			if err := yaml.Unmarshal(data, &existingToken); err != nil {
				return fmt.Errorf("failed to parse token file: %w", err)
			}
			if existingToken.Token != "" {
				slog.Warn("token already exists in file", "path", cfg.TokenPath)
				return nil
			}
		}
	}

	// Create the token
	tokenResp, err := client.CreateToken(ctx, cfg.Username, cfg.Password, "sdk-token")
	if err != nil {
		return fmt.Errorf("failed to create token: %w", err)
	}

	// Save token to Kubernetes secret if configured
	if cfg.K8sSecretName != "" {
		// TODO: dupe k8s, it is a singleton but could be better.
		k8s, err := kube.NewK8sClient()
		if err != nil {
			return fmt.Errorf("failed to create k8s client: %w", err)
		}

		if err := k8s.CreateOrUpdateSecret(ctx, cfg.K8sSecretNamespace, cfg.K8sSecretName, cfg.K8sSecretKey, tokenResp.Token); err != nil {
			return fmt.Errorf("failed to save token to k8s secret: %w", err)
		}
		slog.Info("Token saved to k8s secret", "namespace", cfg.K8sSecretNamespace, "name", cfg.K8sSecretName)
	}

	// Save token to file if configured
	if cfg.TokenPath != "" {
		data, err := yaml.Marshal(tokenResp)
		if err != nil {
			return fmt.Errorf("failed to marshal token config: %w", err)
		}
		if err := os.WriteFile(cfg.TokenPath, data, 0600); err != nil {
			return fmt.Errorf("failed to write token file: %w", err)
		}
		slog.Info("Token saved to file", "path", cfg.TokenPath)
	}

	if cfg.K8sSecretName == "" && cfg.TokenPath == "" {
		// Only display token if not saving to file or k8s secret
		slog.Info("Token created successfully", "token", tokenResp.Token)
	}

	return nil
}

func runChangePassword(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client := technitium.NewClient(cfg)

	if err := client.ChangePassword(ctx, cfg.NewPassword); err != nil {
		slog.Error("failed to change password", "err", err.Error())
	}

	slog.Info("Password changed successfully")
	return nil
}
