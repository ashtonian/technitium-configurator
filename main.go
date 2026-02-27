package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ashtonian/technitium-sdk-go/cmd"
	"github.com/ashtonian/technitium-sdk-go/pkg/technitium"
)

func main() {
	// Create a mutable log level that starts at debug
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelDebug)

	// Create a single handler with source information for debugging
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true, // Include source file/line in debug logs
	})
	slog.SetDefault(slog.New(handler))

	// Define root flags first
	root := flag.NewFlagSet("technitium-cli", flag.ExitOnError)
	configPath := root.String("config", "config.yaml", "Path to client configuration file (default: ./config.yaml)")
	tokenPath := root.String("token-path", "", "Path to token file (default: ./token.yaml)")
	logLevelFlag := root.String("log-level", "", "Override log level (debug, info, warn, error)")

	// Set up usage message
	root.Usage = func() {
		fmt.Fprintf(root.Output(),
			"Usage: %s <command> [options]\n\nOptions:\n", os.Args[0])
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
				"  DNS_TIMEOUT               Timeout for API calls (default: 30s)\n")
	}

	if len(os.Args) < 2 {
		root.Usage()
		os.Exit(1)
	}

	// Parse root flags
	if err := root.Parse(os.Args[2:]); err != nil {
		slog.Error("Failed to parse flags", "error", err)
		os.Exit(1)
	}

	// Load configuration
	cfg := technitium.DefaultConfig()
	cfg.ConfigPath = *configPath
	cfg.TokenPath = *tokenPath

	// Mark ConfigPath as explicitly set if the flag was provided
	root.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			cfg.ConfigPathSet = true
		}
	})

	// Load from file if it exists
	if err := cfg.LoadFromFile(cfg.ConfigPath); err != nil {
		slog.Warn("Failed to load config from file", "error", err, "path", cfg.ConfigPath)
	}

	// Load from environment (overrides file)
	if err := cfg.LoadFromEnv(); err != nil {
		slog.Error("Failed to load config from environment", "error", err)
		os.Exit(1)
	}

	// Apply log level from flag if set, otherwise use config
	if *logLevelFlag != "" {
		switch strings.ToLower(*logLevelFlag) {
		case "debug":
			logLevel.Set(slog.LevelDebug)
		case "info":
			logLevel.Set(slog.LevelInfo)
		case "warn":
			logLevel.Set(slog.LevelWarn)
		case "error":
			logLevel.Set(slog.LevelError)
		default:
			slog.Error("Invalid log level", "level", *logLevelFlag)
			os.Exit(1)
		}
	} else {
		logLevel.Set(cfg.GetLogLevel())
	}

	// Swap to a handler without source information if not in debug mode
	if logLevel.Level() != slog.LevelDebug {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     logLevel,
			AddSource: false,
		})
		slog.SetDefault(slog.New(handler))
	}

	// ---------- run the sub-command ----------
	ctx := context.Background()
	if err := cmd.RunCommand(ctx, cfg, os.Args[1], root.Args()); err != nil {
		slog.Error("Command failed", "error", err, "command", os.Args[1])
		os.Exit(1)
	}
}
