# Command-line reference

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Commands](#commands)
- [Client configuration](#client-configuration)

## Commands

| Command | Description |
|---|---|
| `configure [path...]` | Apply DNS config files. A path may be a file or a directory (its `*.yaml` and `*.yml` files, in name order). Without a path, `DNS_CONFIG_PATH` is used, then the client config file's `config_path`, then `config.yaml` |
| `export [file]` | Write the server's configuration as a DNS config file, to stdout or to `file` (mode `0600`) |
| `create-token` | Create an API token, or keep a stored one the server still accepts, and save it to a file and/or a Kubernetes Secret ([API tokens](api-tokens.md#api-tokens)) |
| `change-password` | Change the password. Succeeds without changes when the new password already works |
| `cluster-state` | Print the cluster state as YAML to stdout: whether the server is in a cluster, its domain and timing options, and each node's type, state, version, addresses and last sync |
| `version` | Print the version, commit and build date |

Flags go after the command: `technitium-configurator configure --log-level debug dns.yaml`. Every command except `version` first waits up to `DNS_WAIT_TIMEOUT` for the server's `/api/status` to answer, so it can start alongside the server. Logs go to stderr; stdout carries only command output: `export`'s and `cluster-state`'s YAML, and `version`.

## Client configuration

The tool takes two kinds of input: **client configuration** (where the server is and how to log in) and **DNS config files** (what the server should look like).

Each client configuration value can come from a default, a client config file (`--config` or `DNS_CLIENT_CONFIG`), an environment variable, or a flag. Later sources win: defaults < file < environment < flags.

| Environment variable | Client config key | Flag | Type | Default | Description |
|---|---|---|---|---|---|
| `DNS_API_URL` | `api_url` | | URL | — (required) | Technitium web service, for example `http://dns-server:5380`. Must not contain credentials, a query or a fragment |
| `DNS_API_TOKEN` | `api_token` | | string | | API token. When set, it is used instead of username and password |
| `DNS_API_TOKEN_FILE` | `api_token_file` | | path | | File holding the API token: the file `create-token` writes, or only the token. Used like `DNS_API_TOKEN`, which may not be set too. Read only by `configure`, `export` and `cluster-state` |
| `DNS_USERNAME` | `username` | | string | | User for login, `create-token` and `change-password` |
| `DNS_PASSWORD` | `password` | | string | | Password (the current one for `change-password`) |
| `DNS_NEW_PASSWORD` | `new_password` | | string | | New password for `change-password` |
| `DNS_CLIENT_CONFIG` | | `--config` | path | | Client config file. Unknown keys are errors; a named file must exist |
| `DNS_CONFIG_PATH` | `config_path` | | path | `config.yaml` | DNS config file or directory `configure` uses when given no path |
| `DNS_TOKEN_PATH` | `token_path` | `--token-path` | path | | Token file `create-token` writes (mode `0600`) |
| `DNS_TIMEOUT` | `timeout` | | duration | `30s` | Timeout for each API call |
| `DNS_WAIT_TIMEOUT` | `wait_timeout` | | duration | `60s` | How long to wait for `/api/status` at start and after a settings change restarts the web service. `0` disables the start-up wait |
| `DNS_LOG_LEVEL` | `log_level` | `--log-level` | enum | `info` | `debug`, `info`, `warn` or `error` |
| `DNS_K8S_SECRET_NAME` | `k8s_secret_name` | | string | | Kubernetes Secret `create-token` stores the token in |
| `DNS_K8S_SECRET_NAMESPACE` | `k8s_secret_namespace` | | string | current namespace | Namespace of that Secret. Unset, it is the current namespace as `kubectl` chooses it: the kubeconfig context's, else the pod's own, else `default` |
| `DNS_K8S_SECRET_KEY` | `k8s_secret_key` | | string | `api-token` | Key in that Secret |

`configure`, `export` and `cluster-state` need a token, a token file, or a username and password. `create-token` and `change-password` need a username and password.

A client config file:

<!-- docs-test: not a DNS config -->
```yaml
api_url: "http://dns-server:5380"
username: "admin"
password: "your-password"
timeout: 30s
wait_timeout: 60s
log_level: "info"
```

```bash
technitium-configurator configure --config client.yaml dns/
```
