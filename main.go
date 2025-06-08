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

func main() {
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(l)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s <command> [options]\n\nCommands:\n  configure <config.yaml>    Configure DNS server using the provided config file\n  create-token              Create an API token and save it to token.yaml\n\nEnvironment variables:\n  DNS_API_URL               Required for both commands\n  DNS_API_TOKEN             Required for configure command\n  DNS_USERNAME              Required for create-token command if not in credentials.yaml\n  DNS_PASSWORD              Required for create-token command if not in credentials.yaml\n", os.Args[0])
		flag.PrintDefaults()
	}

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)
	flag.Parse()

	switch command {
	case "configure":
		runConfigure()
	case "create-token":
		runCreateToken()
	default:
		slog.Error("Unknown command", "command", command)
		flag.Usage()
		os.Exit(1)
	}
}

func runConfigure() {
	apiURL := os.Getenv("DNS_API_URL")
	if apiURL == "" {
		slog.Error("DNS_API_URL not set")
		os.Exit(1)
	}

	// Try to get token from environment variable first
	apiToken := os.Getenv("DNS_API_TOKEN")
	if apiToken == "" {
		// If not in environment, try to read from token.yaml
		if _, err := os.Stat("token.yaml"); err == nil {
			data, err := os.ReadFile("token.yaml")
			if err != nil {
				slog.Error("Failed to read token.yaml", "error", err)
				os.Exit(1)
			}
			var tokenResp technitium.CreateTokenResponse
			if err := yaml.Unmarshal(data, &tokenResp); err != nil {
				slog.Error("Failed to parse token.yaml", "error", err)
				os.Exit(1)
			}
			if tokenResp.Token == "" {
				slog.Error("No token found in token.yaml")
				os.Exit(1)
			}
			apiToken = tokenResp.Token
		} else {
			slog.Error("DNS_API_TOKEN not set and token.yaml not found")
			os.Exit(1)
		}
	}

	cfgPath := "config.yaml"
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

	ctx := context.Background()
	client := technitium.NewClient(apiURL, apiToken)

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
	apiURL := os.Getenv("DNS_API_URL")
	if apiURL == "" {
		slog.Error("DNS_API_URL not set")
		os.Exit(1)
	}

	// Check if token.yaml exists and has a valid token
	var existingToken technitium.CreateTokenResponse
	if _, err := os.Stat("token.yaml"); err == nil {
		data, err := os.ReadFile("token.yaml")
		if err != nil {
			slog.Error("Failed to read token.yaml", "error", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &existingToken); err != nil {
			slog.Error("Failed to parse token.yaml", "error", err)
			os.Exit(1)
		}
		if existingToken.Token != "" {
			slog.Error("token.yaml already exists with a valid token")
			os.Exit(1)
		}
	}

	// Try to read credentials from credentials.yaml first
	var creds config.Credentials
	if _, err := os.Stat("credentials.yaml"); err == nil {
		data, err := os.ReadFile("credentials.yaml")
		if err != nil {
			slog.Error("Failed to read credentials.yaml", "error", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &creds); err != nil {
			slog.Error("Failed to parse credentials.yaml", "error", err)
			os.Exit(1)
		}
	} else {
		// Fall back to environment variables
		creds.Username = os.Getenv("DNS_USERNAME")
		creds.Password = os.Getenv("DNS_PASSWORD")
	}

	if creds.Username == "" || creds.Password == "" {
		slog.Error("DNS_USERNAME and DNS_PASSWORD environment variables or credentials.yaml required")
		os.Exit(1)
	}

	// Create a temporary client without token
	client := technitium.NewClient(apiURL, "")

	// Create the token
	ctx := context.Background()
	tokenResp, err := client.CreateToken(ctx, creds.Username, creds.Password, "sdk-token")
	if err != nil {
		slog.Error("Failed to create token", "error", err)
		os.Exit(1)
	}

	// Save the token to token.yaml
	data, err := yaml.Marshal(tokenResp)
	if err != nil {
		slog.Error("Failed to marshal token config", "error", err)
		os.Exit(1)
	}
	if err := os.WriteFile("token.yaml", data, 0600); err != nil {
		slog.Error("Failed to write token.yaml", "error", err)
		os.Exit(1)
	}

	slog.Info("Token created and saved to token.yaml")
}
