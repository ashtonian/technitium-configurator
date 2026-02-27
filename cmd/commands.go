package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
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
	"cluster-state": {
		Name:        "cluster-state",
		Description: "Display the current cluster state",
		Run:         runClusterState,
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
	client, err := technitium.NewClient(cfg)
	if err != nil {
		return err
	}

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

	// Apply DNS settings BEFORE cluster init.  Cluster init creates a
	// cluster-catalog zone with its own TSIG key; if we set DNS settings
	// (including the user's TSIG key list) afterward, the API rejects the
	// call because it would remove the cluster-catalog key.  By applying
	// DNS settings first the user's keys are set cleanly, and cluster init
	// adds its own key on top.
	//
	// The merge logic below is still kept as a safety net for re-runs where
	// the cluster already exists and has internal TSIG keys.
	if !reflect.DeepEqual(dnsCfg.DNSSettings, technitium.DnsSettings{}) {
		// Merge configured TSIG keys with any existing server keys (e.g.
		// cluster-internal catalog keys from a previous cluster init) so we
		// don't accidentally remove keys the server needs on re-run.
		existing, err := client.GetDNSSettings(ctx)
		if err != nil {
			slog.Warn("failed to fetch existing DNS settings for TSIG merge, proceeding without merge", "error", err)
		}
		if existing != nil && len(existing.TsigKeys) > 0 {
			cfgCount := len(dnsCfg.DNSSettings.TsigKeys)
			dnsCfg.DNSSettings.TsigKeys = mergeTsigKeys(existing.TsigKeys, dnsCfg.DNSSettings.TsigKeys)
			slog.Debug("merged TSIG keys", "server", len(existing.TsigKeys), "configured", cfgCount, "merged", len(dnsCfg.DNSSettings.TsigKeys))
		}

		if err := client.SetDNSSettings(ctx, dnsCfg.DNSSettings); err != nil {
			return fmt.Errorf("failed to set DNS settings: %w", err)
		}
		slog.Info("DNS settings configured", "server", cfg.APIURL)
	}

	// Apply cluster configuration AFTER DNS settings (see comment above).
	if dnsCfg.Cluster != nil {
		if err := applyCluster(ctx, client, cfg, dnsCfg.Cluster); err != nil {
			return err
		}
	}

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

		// Retry zone options update — the API sometimes rejects immediate updates
		var zoneOptsErr error
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(1 * time.Second)
			}
			if _, zoneOptsErr = client.SetZoneOptions(ctx, opts); zoneOptsErr == nil {
				break
			}
		}
		if zoneOptsErr != nil {
			slog.Error("Failed to update zone options", "zone", z.Zone, "error", zoneOptsErr)
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
		if err := client.InstallApp(ctx, req); err != nil {
			slog.Error("Failed to install app", "error", err, "app", app.Name)
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

		if _, err := client.SetAppConfig(ctx, reqConfig); err != nil {
			slog.Error("Failed to set app config", "error", err, "app", app.Name)
		} else {
			slog.Info("App configured", "app", app.Name)
		}
	}

	slog.Info("Configuration complete")
	return nil
}

func applyCluster(ctx context.Context, client *technitium.Client, cfg *technitium.ClientConfig, cc *technitium.ClusterConfig) error {
	switch cc.Mode {
	case "primary":
		if cc.Domain == "" {
			return fmt.Errorf("cluster domain is required for primary mode")
		}
		if cc.NodeIPs == "" {
			return fmt.Errorf("cluster nodeIPs is required for primary mode")
		}
	case "secondary":
		if cc.NodeIPs == "" {
			return fmt.Errorf("cluster nodeIPs is required for secondary mode")
		}
		if cc.PrimaryURL == "" {
			return fmt.Errorf("cluster primaryURL is required for secondary mode")
		}
		if cc.PrimaryUsername == "" {
			return fmt.Errorf("cluster primaryUsername is required for secondary mode")
		}
		if cc.PrimaryPassword == "" {
			return fmt.Errorf("cluster primaryPassword is required for secondary mode")
		}
	default:
		return fmt.Errorf("invalid cluster mode %q: must be \"primary\" or \"secondary\"", cc.Mode)
	}

	state, err := client.GetClusterState(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster state: %w", err)
	}

	if state.ClusterInitialized {
		slog.Info("Cluster already initialized, skipping",
			"domain", state.ClusterDomain,
			"nodes", len(state.Nodes))
		return nil
	}

	if cc.Mode == "primary" {
		if _, err := client.ClusterInit(ctx, cc.Domain, cc.NodeIPs); err != nil {
			return fmt.Errorf("failed to initialize cluster: %w", err)
		}
		slog.Info("Cluster initialized", "domain", cc.Domain)
	} else {
		req := technitium.ClusterJoinRequest{
			SecondaryNodeIPs:    cc.NodeIPs,
			PrimaryNodeURL:      cc.PrimaryURL,
			PrimaryNodeIP:       cc.PrimaryIP,
			PrimaryNodeUsername: cc.PrimaryUsername,
			PrimaryNodePassword: cc.PrimaryPassword,
			PrimaryNodeTotp:     cc.PrimaryTotp,
			IgnoreCertErrors:    cc.IgnoreCertErrors,
		}
		if _, err := client.ClusterJoin(ctx, req); err != nil {
			return fmt.Errorf("failed to join cluster: %w", err)
		}
		slog.Info("Joined cluster", "primaryURL", cc.PrimaryURL)
	}

	// After cluster init/join the server's internal state changes and the
	// previous session token may be invalidated.  Wait briefly for the
	// server to stabilize, then re-authenticate so the rest of the
	// configure pipeline (DNS settings, zones, records, …) has a valid
	// session.
	slog.Info("Waiting for server to stabilize after cluster operation")
	time.Sleep(5 * time.Second)

	if cfg.Username != "" && cfg.Password != "" {
		var loginErr error
		for i := 0; i < 3; i++ {
			if i > 0 {
				time.Sleep(5 * time.Second)
			}
			if _, loginErr = client.Login(ctx, cfg.Username, cfg.Password); loginErr == nil {
				slog.Info("Re-authenticated after cluster operation")

				// Apply cluster timing options (primary only)
				if cc.Mode == "primary" {
					optReq := technitium.ClusterOptionsRequest{
						HeartbeatRefreshIntervalSecs: cc.HeartbeatRefreshIntervalSecs,
						HeartbeatRetryIntervalSecs:   cc.HeartbeatRetryIntervalSecs,
						ConfigRefreshIntervalSecs:    cc.ConfigRefreshIntervalSecs,
						ConfigRetryIntervalSecs:      cc.ConfigRetryIntervalSecs,
					}
					if !optReq.IsEmpty() {
						if err := client.SetClusterOptions(ctx, optReq); err != nil {
							return fmt.Errorf("failed to set cluster options: %w", err)
						}
						slog.Info("Cluster options configured",
							"configRefreshInterval", optReq.ConfigRefreshIntervalSecs,
							"configRetryInterval", optReq.ConfigRetryIntervalSecs,
							"heartbeatRefreshInterval", optReq.HeartbeatRefreshIntervalSecs,
							"heartbeatRetryInterval", optReq.HeartbeatRetryIntervalSecs)
					}
				}

				return nil
			}
			slog.Debug("Re-login attempt failed, retrying", "attempt", i+1, "error", loginErr)
		}
		return fmt.Errorf("failed to re-authenticate after cluster operation: %w", loginErr)
	}

	return nil
}

func runCreateToken(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client, err := technitium.NewClient(cfg)
	if err != nil {
		return err
	}

	// Create a single K8s client if needed for secret operations
	var k8s *kube.K8sClient
	if cfg.K8sSecretName != "" {
		k8s, err = kube.NewK8sClient()
		if err != nil {
			return fmt.Errorf("failed to create k8s client: %w", err)
		}

		existingToken, err := k8s.CheckSecretToken(ctx, cfg.K8sSecretNamespace, cfg.K8sSecretName, cfg.K8sSecretKey)
		if err != nil {
			slog.Warn("Failed to check k8s secret", "error", err, "secret", cfg.K8sSecretName)
		} else if existingToken != "" {
			slog.Warn("token already exists in k8s secret", "secret", fmt.Sprintf("%s/%s", cfg.K8sSecretNamespace, cfg.K8sSecretName))
			return nil
		}
	}

	// Check for existing token in file if configured
	if cfg.TokenPath != "" {
		if _, err := os.Stat(cfg.TokenPath); err == nil {
			data, err := os.ReadFile(cfg.TokenPath)
			if err != nil {
				return fmt.Errorf("failed to read token file: %w", err)
			}
			var existingToken technitium.CreateTokenResponse
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
	if k8s != nil {
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

	if k8s == nil && cfg.TokenPath == "" {
		slog.Info("Token created successfully (not saved to file or k8s secret)")
	}

	return nil
}

func runChangePassword(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client, err := technitium.NewClient(cfg)
	if err != nil {
		return err
	}

	if err := client.ChangePassword(ctx, cfg.Password, cfg.NewPassword); err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	slog.Info("Password changed successfully")
	return nil
}

func runClusterState(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client, err := technitium.NewClient(cfg)
	if err != nil {
		return err
	}

	state, err := client.GetClusterState(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster state: %w", err)
	}

	slog.Info("Cluster state",
		"initialized", state.ClusterInitialized,
		"domain", state.ClusterDomain,
		"version", state.Version,
		"nodes", len(state.Nodes))

	for _, n := range state.Nodes {
		slog.Info("Cluster node",
			"id", n.ID,
			"name", n.Name,
			"type", n.Type,
			"state", n.State,
			"url", n.URL,
			"ipAddresses", n.IPAddresses,
			"lastSeen", n.LastSeen,
			"upSince", n.UpSince)
	}

	return nil
}

// mergeTsigKeys combines existing server TSIG keys with user-configured keys.
// Configured keys take precedence (by keyName); existing keys not present in
// the config (e.g. cluster-catalog keys) are preserved.
func mergeTsigKeys(existing, configured []technitium.TsigKey) []technitium.TsigKey {
	configuredNames := make(map[string]bool, len(configured))
	for _, k := range configured {
		configuredNames[k.KeyName] = true
	}

	merged := make([]technitium.TsigKey, len(configured))
	copy(merged, configured)
	for _, k := range existing {
		if !configuredNames[k.KeyName] {
			merged = append(merged, k)
		}
	}
	return merged
}
