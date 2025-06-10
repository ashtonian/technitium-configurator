package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ashtonian/technitium-sdk-go/pkg/config"
	"github.com/ashtonian/technitium-sdk-go/pkg/technitium"
	"gopkg.in/yaml.v3"
)

var (
	configPath string
	clientCfg  *config.ClientConfig
)

func init() {
	// Set up command line flags
	flag.StringVar(&configPath, "config", "", "Path to client configuration file (default: ./client.yaml)")
}

// getClient returns an authenticated client based on the configuration
func getClient(ctx context.Context) (*technitium.Client, error) {
	client := technitium.NewClient(clientCfg.APIURL, clientCfg.APIToken)

	// If no API token is provided, login with username/password
	if clientCfg.APIToken == "" {
		if _, err := client.Login(ctx, clientCfg.Username, clientCfg.Password); err != nil {
			return nil, fmt.Errorf("failed to login: %w", err)
		}
	}

	return client, nil
}

func main() {
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(l)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s [options] <command> [command-options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(),
			"\nCommands:\n"+
				"  configure <config.yaml>    Configure DNS server using the provided config file\n"+
				"  create-token              Create an API token and save it to token.yaml\n"+
				"  change-password           Change the password for the current user\n\n"+
				"Configuration:\n"+
				"  Configuration can be provided via:\n"+
				"  1. YAML file (default: ./client.yaml)\n"+
				"  2. Environment variables (overrides YAML)\n"+
				"  3. Command line flags (overrides both)\n\n"+
				"Environment variables:\n"+
				"  DNS_API_URL               Required for all commands\n"+
				"  DNS_API_TOKEN             Optional, used for API token authentication\n"+
				"  DNS_USERNAME              Required for create-token and change-password\n"+
				"  DNS_PASSWORD              Required for create-token and change-password\n"+
				"  DNS_NEW_PASSWORD          Required for change-password\n"+
				"  DNS_TOKEN_PATH            Path to token file (default: token.yaml)\n")
	}

	// Parse flags before command
	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Initialize configuration
	clientCfg = config.DefaultConfig()

	// Load configuration from file if specified or use default
	if configPath == "" {
		configPath = "client.yaml"
	}
	if err := clientCfg.LoadFromFile(configPath); err != nil {
		slog.Error("Failed to load config file", "error", err, "path", configPath)
		os.Exit(1)
	}

	// Override with environment variables
	if err := clientCfg.LoadFromEnv(); err != nil {
		slog.Error("Failed to load environment variables", "error", err)
		os.Exit(1)
	}

	// Get command and remaining args
	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)
	flag.Parse()

	// Validate configuration for the command
	if err := clientCfg.Validate(command); err != nil {
		slog.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	switch command {
	case "configure":
		runConfigure()
	case "create-token":
		runCreateToken()
	case "change-password":
		runChangePassword()
	default:
		slog.Error("Unknown command", "command", command)
		flag.Usage()
		os.Exit(1)
	}
}

func runConfigure() {
	ctx := context.Background()
	client, err := getClient(ctx)
	if err != nil {
		slog.Error("Failed to get client", "error", err)
		os.Exit(1)
	}

	cfgPath := clientCfg.ConfigPath
	if flag.NArg() > 0 {
		cfgPath = flag.Arg(0)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		slog.Error("Failed to read config", "error", err)
		os.Exit(1)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		slog.Error("Failed to parse config", "error", err)
		os.Exit(1)
	}

	// Apply DNS settings
	if err := client.SetDNSSettings(ctx, cfg.DNSSettings); err != nil {
		slog.Error("Failed to set DNS settings", "error", err)
	} else {
		slog.Info("DNS settings configured")
	}

	// Configure zones
	for _, z := range cfg.Zones {
		zoneReq := technitium.ZoneCreateRequest{
			Zone:                       z.Zone,
			Type:                       z.Type,
			Catalog:                    z.Catalog,
			UseSoaSerialDateScheme:     z.UseSoaSerialDateScheme,
			PrimaryNameServerAddresses: z.PrimaryNameServerAddresses,
			ZoneTransferProtocol:       z.ZoneTransferProtocol,
			TsigKeyName:                z.TsigKeyName,
			ValidateZone:               z.ValidateZone,
			InitializeForwarder:        z.InitializeForwarder,
			Protocol:                   z.Protocol,
			Forwarder:                  z.Forwarder,
			DnssecValidation:           z.DnssecValidation,
			ProxyType:                  z.ProxyType,
			ProxyAddress:               z.ProxyAddress,
			ProxyPort:                  z.ProxyPort,
			ProxyUsername:              z.ProxyUsername,
			ProxyPassword:              z.ProxyPassword,
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
			opts.ACLSettings = technitium.ACLSettings{
				QueryAccess:                     z.ACLSettings.QueryAccess,
				QueryAccessNetworkACL:           z.ACLSettings.QueryAccessNetworkACL,
				ZoneTransfer:                    z.ACLSettings.ZoneTransfer,
				ZoneTransferNetworkACL:          z.ACLSettings.ZoneTransferNetworkACL,
				ZoneTransferTsigKeys:            z.ACLSettings.ZoneTransferTsigKeys,
				Notify:                          z.ACLSettings.Notify,
				NotifyNameServers:               z.ACLSettings.NotifyNameServers,
				NotifySecondaryCatalogNameSrvrs: z.ACLSettings.NotifySecondaryCatalogNameSrvrs,
				Update:                          z.ACLSettings.Update,
				UpdateNetworkACL:                z.ACLSettings.UpdateNetworkACL,
				UpdateSecPolicies:               z.ACLSettings.UpdateSecPolicies,
			}
		}
		// api doesn't like immediate updates to zone sometimes..
		time.Sleep(1. * time.Second)

		if _, err := client.SetZoneOptions(ctx, opts); err != nil {
			slog.Error("Failed to update zone options", "zone", z.Zone, "error", err)
		} else {
			slog.Info("Zone configured", "zone", z.Zone)
		}
	}

	// Configure records
	for _, r := range cfg.Records {
		recordReq := technitium.AddRecordRequest{
			Domain:          r.Domain,
			Type:            r.Type,
			Zone:            r.Zone,
			RecordMeta:      r.RecordMeta,
			Overwrite:       r.Overwrite,
			IPAddress:       r.IPAddress,
			Ptr:             r.Ptr,
			CreatePtrZone:   r.CreatePtrZone,
			UpdateSvcbHints: r.UpdateSvcbHints,
			NameServer:      r.NameServer,
			Glue:            r.Glue,
			CName:           r.CName,
			PtrName:         r.PtrName,
			DName:           r.DName,
			AName:           r.AName,
			Exchange:        r.Exchange,
			Preference:      r.Preference,
			Text:            r.Text,
			SplitText:       r.SplitText,
			Mailbox:         r.Mailbox,
			TxtDomain:       r.TxtDomain,
			Priority:        r.Priority,
			Weight:          r.Weight,
			Port:            r.Port,
			Target:          r.Target,
			RData:           r.RData,
		}

		if _, err := client.AddRecord(ctx, recordReq); err != nil {
			slog.Error("Failed to add record", "domain", r.Domain, "error", err)
		} else {
			slog.Info("Record configured", "domain", r.Domain)
		}
	}

	// Install and configure apps
	for _, app := range cfg.Apps {
		slog.Info("Installing app", "app", app.Name)

		// Install the app
		req := technitium.AppInstallRequest{
			Name: app.Name,
			Url:  app.Url,
		}
		err = client.InstallApp(ctx, req)
		if err != nil {
			slog.Error("Failed to install app", "error", err, "app", app.Name)
		}

		config, err := app.GetConfigJSON()
		if err != nil {
			slog.Error("Failed to get app config", "error", err, "app", app.Name)
		}

		reqConfig := technitium.AppConfigRequest{
			Name:   app.Name,
			Config: config,
		}

		_, err = client.SetAppConfig(ctx, reqConfig)
		if err != nil {
			slog.Error("Failed to set app config", "error", err, "app", app.Name)
		}
	}

	slog.Info("Configuration complete!")
}

func runCreateToken() {
	ctx := context.Background()
	client, err := getClient(ctx)
	if err != nil {
		slog.Error("Failed to get client", "error", err)
		os.Exit(1)
	}

	// Check if token file exists and has a valid token
	var existingToken technitium.CreateTokenResponse
	if _, err := os.Stat(clientCfg.TokenPath); err == nil {
		data, err := os.ReadFile(clientCfg.TokenPath)
		if err != nil {
			slog.Error("Failed to read token file", "error", err, "path", clientCfg.TokenPath)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &existingToken); err != nil {
			slog.Error("Failed to parse token file", "error", err, "path", clientCfg.TokenPath)
			os.Exit(1)
		}
		if existingToken.Token != "" {
			slog.Error("Token file already exists with a valid token", "path", clientCfg.TokenPath)
			os.Exit(1)
		}
	}

	// Create the token
	tokenResp, err := client.CreateToken(ctx, clientCfg.Username, clientCfg.Password, "sdk-token")
	if err != nil {
		slog.Error("Failed to create token", "error", err)
		os.Exit(1)
	}

	// Save the token
	data, err := yaml.Marshal(tokenResp)
	if err != nil {
		slog.Error("Failed to marshal token config", "error", err)
		os.Exit(1)
	}
	if err := os.WriteFile(clientCfg.TokenPath, data, 0600); err != nil {
		slog.Error("Failed to write token file", "error", err, "path", clientCfg.TokenPath)
		os.Exit(1)
	}

	slog.Info("Token created and saved", "path", clientCfg.TokenPath)
}

func runChangePassword() {
	ctx := context.Background()
	client, err := getClient(ctx)
	if err != nil {
		slog.Error("Failed to get client", "error", err)
		os.Exit(1)
	}

	if err := client.ChangePassword(ctx, clientCfg.NewPassword); err != nil {
		slog.Error("Failed to change password", "error", err)
		os.Exit(1)
	}

	slog.Info("Password changed successfully")
}
