package cmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
)

// ErrUsage marks a command line the CLI cannot run, such as an unknown
// command, an unknown flag or extra arguments; main exits with 2 for it.
var ErrUsage = errors.New("usage")

// VersionCommand prints build information. It needs no configuration or
// server, so main handles it instead of RunCommand.
const VersionCommand = "version"

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

// Invocation is a parsed command line. Flags that were not given are empty.
type Invocation struct {
	Command          string
	Args             []string
	ClientConfigPath string
	TokenPath        string
	LogLevel         string
}

// ParseArgs parses a command line: the command, then its flags, then its
// arguments. It returns flag.ErrHelp when the command line asks for help and
// an error wrapping ErrUsage when it cannot be run.
func ParseArgs(args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{}, fmt.Errorf("%w: no command given", ErrUsage)
	}
	command, rest := args[0], args[1:]
	switch command {
	case "help", "--help", "-help", "-h":
		if len(rest) > 0 {
			return Invocation{}, fmt.Errorf("%w: help takes no arguments", ErrUsage)
		}
		return Invocation{}, flag.ErrHelp
	case VersionCommand, "--version", "-version":
		if len(rest) > 0 {
			return Invocation{}, fmt.Errorf("%w: version takes no flags or arguments", ErrUsage)
		}
		return Invocation{Command: VersionCommand}, nil
	}

	c, ok := Commands[command]
	if !ok {
		return Invocation{}, fmt.Errorf("%w: unknown command %q", ErrUsage, command)
	}
	inv := Invocation{Command: command}
	flags := newFlagSet(&inv)
	if err := flags.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Invocation{}, flag.ErrHelp
		}
		return Invocation{}, fmt.Errorf("%w: %s: %v", ErrUsage, command, err)
	}
	inv.Args = flags.Args()
	if c.MaxArgs >= 0 && len(inv.Args) > c.MaxArgs {
		return Invocation{}, fmt.Errorf("%w: %s takes at most %d argument(s): %s", ErrUsage, command, c.MaxArgs, c.Usage)
	}
	return inv, nil
}

// newFlagSet binds the command flags to inv. It prints nothing: ParseArgs
// returns parse errors and main decides where usage goes.
func newFlagSet(inv *Invocation) *flag.FlagSet {
	flags := flag.NewFlagSet("technitium-configurator", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	flags.StringVar(&inv.ClientConfigPath, "config", "", "client config file with connection and auth settings (env DNS_CLIENT_CONFIG)")
	flags.StringVar(&inv.TokenPath, "token-path", "", "token file for create-token (env DNS_TOKEN_PATH)")
	flags.StringVar(&inv.LogLevel, "log-level", "", "debug, info, warn or error (env DNS_LOG_LEVEL)")
	return flags
}

// Usage writes the command-line help to w.
func Usage(w io.Writer) {
	_, _ = fmt.Fprintf(w, "Usage: technitium-configurator <command> [flags] [args]\n\nCommands:\n")
	names := make([]string, 0, len(Commands))
	for name := range Commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		_, _ = fmt.Fprintf(w, "  %-18s %s\n", Commands[name].Usage, Commands[name].Description)
	}
	_, _ = fmt.Fprintf(w, "  %-18s %s\n\nFlags (after the command):\n", VersionCommand, "Print the version")
	flags := newFlagSet(&Invocation{})
	flags.SetOutput(w)
	flags.PrintDefaults()
	_, _ = fmt.Fprintf(w, "\n%s", envHelp)
}
