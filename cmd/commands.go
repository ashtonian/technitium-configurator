package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ashtonian/technitium-configurator/v3/pkg/kube"
	"github.com/ashtonian/technitium-configurator/v3/pkg/technitium"
	"gopkg.in/yaml.v3"
)

// tokenName is the name API tokens are created under.
const tokenName = "sdk-token"

// Command represents a command that can be executed
type Command struct {
	Name        string
	Usage       string
	Description string
	// MaxArgs is how many arguments the command takes; -1 means any number.
	MaxArgs int
	Run     func(ctx context.Context, cfg *technitium.ClientConfig, args []string) error
}

// Commands is a map of all available commands
var Commands = map[string]Command{
	"configure": {
		Name:        "configure",
		Usage:       "configure [path...]",
		Description: "Apply the DNS config file: create what is missing, apply settings and options",
		MaxArgs:     -1,
		Run:         runConfigure,
	},
	"create-token": {
		Name:        "create-token",
		Usage:       "create-token",
		Description: "Create an API token, or keep a stored one that is still valid",
		Run:         runCreateToken,
	},
	"change-password": {
		Name:        "change-password",
		Usage:       "change-password",
		Description: "Change the password for the current user (no-op when already changed)",
		Run:         runChangePassword,
	},
	"export": {
		Name:        "export",
		Usage:       "export [file]",
		Description: "Write the server's configuration as a DNS config file (to stdout, or to file)",
		MaxArgs:     1,
		Run:         runExport,
	},
	"cluster-state": {
		Name:        "cluster-state",
		Usage:       "cluster-state",
		Description: "Display the current cluster state",
		Run:         runClusterState,
	},
}

// RunCommand executes the specified command with the given configuration
// ErrUsage marks a command line the CLI cannot run, such as an unknown
// command or extra arguments; main exits with 2 for it.
var ErrUsage = errors.New("usage")

func RunCommand(ctx context.Context, cfg *technitium.ClientConfig, command string, args []string) error {
	cmd, ok := Commands[command]
	if !ok {
		return fmt.Errorf("%w: unknown command %q", ErrUsage, command)
	}
	if cmd.MaxArgs >= 0 && len(args) > cmd.MaxArgs {
		return fmt.Errorf("%w: %s takes at most %d argument(s): %s", ErrUsage, command, cmd.MaxArgs, cmd.Usage)
	}

	if err := cfg.Validate(command); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return cmd.Run(ctx, cfg, args)
}

// newClient builds an API client and waits for the server to answer.
func newClient(ctx context.Context, cfg *technitium.ClientConfig) (*technitium.Client, error) {
	client, err := technitium.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.WaitTimeout > 0 {
		if err := client.WaitReady(ctx, cfg.WaitTimeout, 2*time.Second); err != nil {
			return nil, err
		}
	}
	return client, nil
}

// authenticate uses the API token when one is configured, otherwise logs in.
// authenticate starts a session from the API token, checked with the server
// first, or from the username and password.
func authenticate(ctx context.Context, client *technitium.Client, cfg *technitium.ClientConfig) error {
	if cfg.APIToken != "" {
		if _, err := client.TokenUser(ctx, cfg.APIToken); err != nil {
			return fmt.Errorf("check API token: %w", err)
		}
		client.SetToken(cfg.APIToken)
		return nil
	}
	if err := client.Login(ctx, cfg.Username, cfg.Password, ""); err != nil {
		return fmt.Errorf("login as %q: %w", cfg.Username, err)
	}
	return nil
}

func runConfigure(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	paths := args
	if len(paths) == 0 {
		paths = []string{cfg.ConfigPath}
	}
	desired, err := technitium.LoadConfigPaths(paths)
	if err != nil {
		return err
	}

	client, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}
	if err := authenticateConfigure(ctx, client, cfg, desired.Cluster); err != nil {
		return err
	}

	a := &applier{client: client, cfg: cfg, desired: desired}
	return a.run(ctx)
}

// authenticateConfigure logs in for configure. Joining a cluster replaces a
// secondary's users with the primary's and drops its own API tokens, so
// when the node's token or credentials no longer work, the primary's
// credentials from the cluster section are tried. A one-time password
// cannot be reused on later runs, so that user must not need one.
func authenticateConfigure(ctx context.Context, client *technitium.Client, cfg *technitium.ClientConfig, cc *technitium.ClusterConfig) error {
	err := authenticate(ctx, client, cfg)
	if err == nil || cc == nil || cc.Mode != "secondary" || cc.PrimaryPassword == "" {
		return err
	}
	if cfg.APIToken == "" && cc.PrimaryUsername == cfg.Username && cc.PrimaryPassword == cfg.Password {
		return err
	}
	perr := client.Login(ctx, cc.PrimaryUsername, cc.PrimaryPassword, "")
	switch {
	case perr == nil:
		slog.Info("Logged in with the primary's credentials; this node has joined the cluster", "user", cc.PrimaryUsername)
		return nil
	case errors.Is(perr, technitium.ErrTwoFactorRequired):
		return fmt.Errorf("%w; the primary's user %q also needs a one-time password, which only works for the join; use a primary user without two-factor authentication for later runs", err, cc.PrimaryUsername)
	default:
		return err
	}
}

func runCreateToken(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}

	var k8s *kube.K8sClient
	var secretToken, fileToken string
	if cfg.K8sSecretName != "" {
		k8s, err = kube.NewK8sClient()
		if err != nil {
			return fmt.Errorf("create kubernetes client: %w", err)
		}
		secretToken, err = k8s.CheckSecretToken(ctx, cfg.K8sSecretNamespace, cfg.K8sSecretName, cfg.K8sSecretKey)
		if err != nil && !kube.NotFound(err) && !kube.TokenNotFound(err) {
			return fmt.Errorf("read token secret %s/%s: %w", cfg.K8sSecretNamespace, cfg.K8sSecretName, err)
		}
	}
	if cfg.TokenPath != "" {
		fileToken, err = readTokenFile(cfg.TokenPath)
		if err != nil {
			return err
		}
	}

	// A stored token is reused only if the server still accepts it for the
	// configured user; a redeployed server with fresh storage forgets it.
	token := ""
	for _, candidate := range []string{secretToken, fileToken} {
		if candidate == "" {
			continue
		}
		user, err := client.TokenUser(ctx, candidate)
		switch {
		case err == nil && strings.EqualFold(user, cfg.Username):
			token = candidate
		case err == nil:
			slog.Warn("Stored API token belongs to another user; ignoring it", "tokenUser", user, "user", cfg.Username)
		case errors.Is(err, technitium.ErrInvalidToken):
			slog.Info("Stored API token is no longer valid; creating a new one")
		default:
			return fmt.Errorf("validate stored API token: %w", err)
		}
		if token != "" {
			break
		}
	}

	if token == "" {
		resp, err := client.CreateToken(ctx, cfg.Username, cfg.Password, tokenName)
		if err != nil {
			return fmt.Errorf("create API token: %w", err)
		}
		token = resp.Token
		slog.Info("Created API token", "user", cfg.Username, "tokenName", tokenName)
	} else {
		slog.Info("Stored API token is valid; reusing it", "user", cfg.Username)
	}

	if k8s != nil && secretToken != token {
		if err := k8s.CreateOrUpdateSecret(ctx, cfg.K8sSecretNamespace, cfg.K8sSecretName, cfg.K8sSecretKey, token); err != nil {
			return fmt.Errorf("save API token to secret %s/%s: %w", cfg.K8sSecretNamespace, cfg.K8sSecretName, err)
		}
		slog.Info("Saved API token to Kubernetes secret", "namespace", cfg.K8sSecretNamespace, "name", cfg.K8sSecretName)
	}
	if cfg.TokenPath != "" && fileToken != token {
		rec := technitium.CreateTokenResponse{Username: cfg.Username, TokenName: tokenName, Token: token}
		if err := writeTokenFile(cfg.TokenPath, rec); err != nil {
			return err
		}
		slog.Info("Saved API token to file", "path", cfg.TokenPath)
	}
	return nil
}

func readTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	var rec technitium.CreateTokenResponse
	if err := yaml.Unmarshal(data, &rec); err != nil {
		return "", fmt.Errorf("parse token file %s: %w", path, err)
	}
	return rec.Token, nil
}

// writeTokenFile replaces path atomically with a 0600 file.
func writeTokenFile(path string, rec technitium.CreateTokenResponse) error {
	data, err := yaml.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode token file: %w", err)
	}
	if err := writeFilePrivate(path, data); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}

// writeFilePrivate replaces path with a 0600 file, atomically where it can.
// When the file exists but cannot be replaced, because it is bind-mounted
// into a container or its directory is read-only, it is overwritten in
// place instead.
func writeFilePrivate(path string, data []byte) error {
	err := replaceFile(path, data)
	if err == nil {
		return nil
	}
	if _, statErr := os.Stat(path); statErr != nil {
		return err
	}
	if werr := writeInPlace(path, data); werr != nil {
		return fmt.Errorf("%w (replacing the file failed: %v)", werr, err)
	}
	return nil
}

func replaceFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	// After a successful rename the temp name no longer exists; this only cleans up failures.
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func runExport(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}
	if err := authenticate(ctx, client, cfg); err != nil {
		return err
	}
	conf, notes, err := technitium.Export(ctx, client)
	if err != nil {
		return err
	}
	out, err := technitium.MarshalExport(conf, cfg.APIURL, notes)
	if err != nil {
		return err
	}
	// An export that does not load is a bug; refuse it rather than write it.
	if _, err := technitium.LoadConfig(technitium.Source{Name: "export", Data: out}); err != nil {
		return fmt.Errorf("the export does not load as a config, so it was not written: %w", err)
	}
	if len(args) == 0 {
		_, err := os.Stdout.Write(out)
		return err
	}
	if err := writeFilePrivate(args[0], out); err != nil {
		return fmt.Errorf("write %s: %w", args[0], err)
	}
	slog.Info("Exported configuration", "path", args[0], "zones", len(conf.Zones), "records", len(conf.Records), "apps", len(conf.Apps))
	return nil
}

// writeInPlace overwrites path, making it private before any data is
// written. A file this user cannot chmod is used only if it is private
// already.
func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		info, statErr := f.Stat()
		if statErr != nil || info.Mode().Perm()&0o077 != 0 {
			_ = f.Close()
			return fmt.Errorf("cannot make %s private (mode %v): %w", path, modeOf(info), err)
		}
	}
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func modeOf(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0
	}
	return info.Mode().Perm()
}

func runChangePassword(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}

	// A re-run must succeed, so a working new password means the change is
	// already done. Trying it first keeps steady-state runs free of failed
	// logins, which the server counts toward blocking the client address.
	if err := client.Login(ctx, cfg.Username, cfg.NewPassword, ""); err == nil {
		slog.Info("Password is already set to the new value", "user", cfg.Username)
		return nil
	}
	if err := client.Login(ctx, cfg.Username, cfg.Password, ""); err != nil {
		return fmt.Errorf("login as %q with the current password: %w", cfg.Username, err)
	}
	if err := client.ChangePassword(ctx, cfg.Password, cfg.NewPassword); err != nil {
		return fmt.Errorf("change password for %q: %w", cfg.Username, err)
	}
	slog.Info("Password changed", "user", cfg.Username)
	return nil
}

func runClusterState(ctx context.Context, cfg *technitium.ClientConfig, args []string) error {
	client, err := newClient(ctx, cfg)
	if err != nil {
		return err
	}
	if err := authenticate(ctx, client, cfg); err != nil {
		return err
	}

	state, err := client.GetClusterState(ctx)
	if err != nil {
		return err
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
			"version", n.Version,
			"url", n.URL,
			"ipAddresses", n.IPAddresses,
			"lastSeen", n.LastSeen,
			"upSince", n.UpSince,
			"configLastSynced", n.ConfigLastSynced)
	}

	return nil
}
