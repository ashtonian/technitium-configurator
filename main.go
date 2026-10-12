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
	"sort"
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

const envHelp = `Environment variables:
  DNS_API_URL               URL of the Technitium web service (required)
  DNS_API_TOKEN             API token; used instead of username and password
  DNS_USERNAME              Username for login, create-token and change-password
  DNS_PASSWORD              Password (the current one for change-password)
  DNS_NEW_PASSWORD          New password for change-password
  DNS_CLIENT_CONFIG         Client config file (same as --config)
  DNS_CONFIG_PATH           DNS config file for configure (default: config.yaml)
  DNS_TOKEN_PATH            Token file for create-token
  DNS_TIMEOUT               Timeout for each API call (default: 30s)
  DNS_WAIT_TIMEOUT          Wait for the web service to answer (default: 60s, 0 disables)
  DNS_LOG_LEVEL             debug, info, warn or error (default: info)
  DNS_K8S_SECRET_NAME       Kubernetes Secret create-token stores the token in
  DNS_K8S_SECRET_NAMESPACE  Namespace of that Secret (default: default)
  DNS_K8S_SECRET_KEY        Key in that Secret (default: api-token)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout))
}

// run executes the CLI. Logs go to stderr so stdout carries only command
// output, such as export's YAML.
func run(args []string, stdout io.Writer) int {
	logLevel := new(slog.LevelVar)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	flags := flag.NewFlagSet("technitium-configurator", flag.ContinueOnError)
	flags.SetOutput(stdout)
	clientConfigPath := flags.String("config", "", "client config file with connection and auth settings (env DNS_CLIENT_CONFIG)")
	tokenPath := flags.String("token-path", "", "token file for create-token (env DNS_TOKEN_PATH)")
	logLevelFlag := flags.String("log-level", "", "debug, info, warn or error (env DNS_LOG_LEVEL)")
	flags.Usage = func() { usage(flags) }

	if len(args) == 0 {
		usage(flags)
		return 2
	}
	command := args[0]
	switch command {
	case "version", "--version", "-version":
		_, _ = fmt.Fprintf(stdout, "technitium-configurator %s (commit %s, built %s)\n", version, commit, buildDate)
		return 0
	case "help", "--help", "-help", "-h":
		usage(flags)
		return 0
	}
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}

	// Precedence: defaults < client config file < environment < flags.
	cfg := technitium.DefaultConfig()
	if *clientConfigPath == "" {
		*clientConfigPath = os.Getenv("DNS_CLIENT_CONFIG")
	}
	if *clientConfigPath != "" {
		if err := cfg.LoadFromFile(*clientConfigPath); err != nil {
			slog.Error("Invalid client config", "error", err)
			return 1
		}
	}
	if err := cfg.LoadFromEnv(); err != nil {
		slog.Error("Invalid environment", "error", err)
		return 1
	}
	if *tokenPath != "" {
		cfg.TokenPath = *tokenPath
	}
	if *logLevelFlag != "" {
		cfg.LogLevel = technitium.LogLevel(*logLevelFlag)
	}
	logLevel.Set(cfg.GetLogLevel())
	if logLevel.Level() == slog.LevelDebug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel, AddSource: true})))
	}
	slog.Debug("Starting", "version", version, "commit", commit, "command", command)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := cmd.RunCommand(ctx, cfg, command, flags.Args()); err != nil {
		slog.Error("Command failed", "error", err, "command", command)
		if errors.Is(err, cmd.ErrUsage) {
			usage(flags)
			return 2
		}
		return 1
	}
	return 0
}

func usage(flags *flag.FlagSet) {
	out := flags.Output()
	_, _ = fmt.Fprintf(out, "Usage: technitium-configurator <command> [flags] [args]\n\nCommands:\n")
	names := make([]string, 0, len(cmd.Commands))
	for name := range cmd.Commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = fmt.Fprintf(out, "  %-18s %s\n", cmd.Commands[name].Usage, cmd.Commands[name].Description)
	}
	_, _ = fmt.Fprintf(out, "  %-18s %s\n\nFlags (after the command):\n", "version", "Print the version")
	flags.PrintDefaults()
	_, _ = fmt.Fprintf(out, "\n%s", envHelp)
}
