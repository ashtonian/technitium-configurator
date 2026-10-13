package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ashtonian/technitium-configurator/v3/cmd"
	"github.com/ashtonian/technitium-configurator/v3/pkg/technitium"
)

// Set at build time with -ldflags "-X main.version=...".
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns its exit code. Logs and usage errors go to
// stderr so stdout carries only command output, such as export's YAML.
func run(args []string, stdout, stderr io.Writer) int {
	logLevel := new(slog.LevelVar)
	slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: logLevel})))

	inv, err := cmd.ParseArgs(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		cmd.Usage(stdout)
		return 0
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "%v\n\n", err)
		cmd.Usage(stderr)
		return 2
	case inv.Command == cmd.VersionCommand:
		_, _ = fmt.Fprintf(stdout, "technitium-configurator %s (commit %s, built %s)\n", version, commit, buildDate)
		return 0
	}

	// Precedence: defaults < client config file < environment < flags.
	cfg := technitium.DefaultConfig()
	clientConfigPath := inv.ClientConfigPath
	if clientConfigPath == "" {
		clientConfigPath = os.Getenv("DNS_CLIENT_CONFIG")
	}
	if clientConfigPath != "" {
		if err := cfg.LoadFromFile(clientConfigPath); err != nil {
			slog.Error("Invalid client config", "error", err)
			return 1
		}
	}
	if err := cfg.LoadFromEnv(); err != nil {
		slog.Error("Invalid environment", "error", err)
		return 1
	}
	if inv.TokenPath != "" {
		cfg.TokenPath = inv.TokenPath
	}
	if inv.LogLevel != "" {
		cfg.LogLevel = technitium.LogLevel(inv.LogLevel)
	}
	logLevel.Set(cfg.GetLogLevel())
	if logLevel.Level() == slog.LevelDebug {
		slog.SetDefault(slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: logLevel, AddSource: true})))
	}
	slog.Debug("Starting", "version", version, "commit", commit, "command", inv.Command)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cmd.RunCommand(ctx, cfg, inv.Command, inv.Args); err != nil {
		slog.Error("Command failed", "error", err, "command", inv.Command)
		return 1
	}
	return 0
}
