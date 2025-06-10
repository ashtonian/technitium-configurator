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

	// Set up command line flags
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to client configuration file (default: ./client.yaml)")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage: %s [options] <command> [command-options]\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\nCommands:\n")
		for name, cmd := range cmd.Commands {
			fmt.Fprintf(flag.CommandLine.Output(), "  %-20s %s\n", name, cmd.Description)
		}
		fmt.Fprintf(flag.CommandLine.Output(),
			"\nConfiguration:\n"+
				"  Configuration can be provided via:\n"+
				"  1. YAML file (default: ./client.yaml)\n"+
				"  2. Environment variables (overrides YAML)\n"+
				"Environment variables:\n"+
				"  DNS_API_URL               Required for all commands\n"+
				"  DNS_API_TOKEN             Optional, used for API token authentication\n"+
				"  DNS_USERNAME              Required for create-token and change-password\n"+
				"  DNS_PASSWORD              Required for create-token and change-password\n"+
				"  DNS_NEW_PASSWORD          Required for change-password\n"+
				"  DNS_TOKEN_PATH            Path to token file (default: token.yaml)\n"+
				"  DNS_TIMEOUT              Timeout for API calls (default: 30s)\n")
	}

	flag.Parse()

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Get command and remaining args
	command := os.Args[1]
	os.Args = append(os.Args[:1], os.Args[2:]...)
	flag.Parse()

	// Load configuration
	cfg := technitium.DefaultConfig()
	if configPath == "" {
		configPath = "client.yaml"
	}

	// Only try to load config file if it exists
	if _, err := os.Stat(configPath); err == nil {
		if err := cfg.LoadFromFile(configPath); err != nil {
			slog.Error("Failed to load config file", "error", err, "path", configPath)
			os.Exit(1)
		}
	} else {
		slog.Debug("No config file found, using environment variables only", "path", configPath)
	}

	// Override with environment variables
	if err := cfg.LoadFromEnv(); err != nil {
		slog.Error("Failed to load environment variables", "error", err)
		os.Exit(1)
	}

	// Run the command
	ctx := context.Background()
	if err := cmd.RunCommand(ctx, cfg, command, flag.Args()); err != nil {
		slog.Error("Command failed", "error", err, "command", command)
		os.Exit(1)
	}
}
