package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/ashtonian/technitium-sdk-go/cmd"
	"github.com/ashtonian/technitium-sdk-go/pkg/technitium"
)

func main() {
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(l)

	// ---------- root flags ----------
	root := flag.NewFlagSet("technitium-cli", flag.ExitOnError)
	configPath := root.String("config", "config.yaml", "Path to client configuration file (default: ./config.yaml)")
	tokenPath := root.String("token-path", "", "Path to token file (default: ./token.yaml)")

	// Set up usage message
	root.Usage = func() {
		fmt.Fprintf(root.Output(),
			"Usage: %s [options] <command> [command-options]\n\nOptions:\n", os.Args[0])
		root.PrintDefaults()
		fmt.Fprintf(root.Output(), "\nCommands:\n")
		for name, cmd := range cmd.Commands {
			fmt.Fprintf(root.Output(), "  %-20s %s\n", name, cmd.Description)
		}
		fmt.Fprintf(root.Output(),
			"\nConfiguration:\n"+
				"  Configuration can be provided via:\n"+
				"  1. YAML file (default: ./config.yaml)\n"+
				"  2. Environment variables (overrides YAML)\n"+
				"Environment variables:\n"+
				"  DNS_API_URL               Required for all commands\n"+
				"  DNS_API_TOKEN             Optional, used for API token authentication\n"+
				"  DNS_USERNAME              Required for create-token and change-password\n"+
				"  DNS_PASSWORD              Required for create-token and change-password\n"+
				"  DNS_NEW_PASSWORD          Required for change-password\n"+
				"  DNS_TOKEN_PATH            Path to token file (default: token.yaml)\n"+
				"  DNS_CONFIG_PATH           Path to config file (default: config.yaml)\n"+
				"  DNS_TIMEOUT              Timeout for API calls (default: 30s)\n")
	}

	if len(os.Args) < 2 {
		root.Usage()
		os.Exit(1)
	}

	// Get command and parse remaining args
	command := os.Args[1]
	if err := root.Parse(os.Args[2:]); err != nil {
		slog.Error("Failed to parse flags", "error", err)
		os.Exit(1)
	}

	// ---------- load/override configuration ----------
	cfg := technitium.DefaultConfig()

	// Honour the flags
	cfg.ConfigPath = *configPath
	if *tokenPath != "" {
		cfg.TokenPath = *tokenPath
	}

	// Load from file if it exists
	if _, err := os.Stat(cfg.ConfigPath); err == nil {
		if err := cfg.LoadFromFile(cfg.ConfigPath); err != nil {
			slog.Error("Failed to load config file", "error", err, "path", cfg.ConfigPath)
			os.Exit(1)
		}
	} else {
		slog.Debug("No config file found, using environment variables only", "path", cfg.ConfigPath)
	}

	// Override with environment variables
	if err := cfg.LoadFromEnv(); err != nil {
		slog.Error("Failed to load environment variables", "error", err)
		os.Exit(1)
	}

	// ---------- run the sub-command ----------
	ctx := context.Background()
	if err := cmd.RunCommand(ctx, cfg, command, root.Args()); err != nil {
		slog.Error("Command failed", "error", err, "command", command)
		os.Exit(1)
	}
}
