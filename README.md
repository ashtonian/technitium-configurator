# Technitium Configurator

A Go tool for configuring Technitium DNS Server in a declarative fashion, supporting both one-time setup and continuous configuration management (see limitations). Also supports updating user password, and creating/syncing a kube secret with an api token value.

## Why

DNS is *critical* and therefore its configuration should be easily repeatable. Technetium is one of the only open source, authoritative servers with a UI, that supports additional feature sets like dns sink hole, RFC2136 support (external-dns), split horizon ect... However its config files are currently stored in binary with complex versioning/logic, and there isn't a declarative solution. To address this, an over engineered configuration utility was born.

PowerDNS was also considered however they are moving features to a commercial platform.

## Features

- Create and manage API tokens
- Update user passwords
- Configure DNS server settings
- Manage DNS zones and records
- Install and configure apps

## Supported Apps

Currently supports:

- Advanced Blocking (DNS blocking and filtering)
- Advanced Forwarding (DNS forwarding and proxy)

### Adding New Apps

To add support for a new app:

1. Add a new config struct in `pkg/technitium/`, struct needs json and yaml tags.
    1. The `UnmarshalYAML` and field json/yaml struct tags should account for any default value handling the app is expecting.

2. Add a case in the app configuration switch statement in `main.go`:

```go
	switch a.Name {
	case "Advanced Blocking":
		cfg = new(BlockingConfig)
	case "New App":
		cfg = new(NewAppConfig)
    ...
	}
```


## Usage

### Running As container

The configurator is available as a container image:

```bash
docker pull ashtonian/technitium-configurator:latest
```

### Configuration Methods

The configurator supports two methods of configuration:

1. **Environment Variables**
   - All settings can be provided via environment variables
   - Environment variables take precedence over YAML config
   - No config files required

2. **YAML Configuration Files**
   - Traditional file-based configuration
   - Can be mixed with environment variables
   - Environment variables override YAML settings

### Available Environment Variables

```
DNS_API_URL               Required: URL of the DNS server API (e.g., http://dns-server:5380)
DNS_API_TOKEN            Optional: API token for authentication
DNS_USERNAME             Required for create-token and change-password commands
DNS_PASSWORD             Required for create-token and change-password commands
DNS_NEW_PASSWORD         Required for change-password command
DNS_TOKEN_PATH           Optional: Path to token file (default: token.yaml)
DNS_CONFIG_PATH          Optional: Path to config file (default: config.yaml)
DNS_TIMEOUT              Optional: Timeout for API calls (default: 30s)
DNS_LOG_LEVEL            Optional: Logging level (debug, info, warn, error) (default: info)
DNS_K8S_SECRET_NAME      Optional: Name of Kubernetes secret to store token in
DNS_K8S_SECRET_NAMESPACE Optional: Namespace of Kubernetes secret (default: default)
DNS_K8S_SECRET_KEY       Optional: Key in Kubernetes secret to store token (default: api-token)
```

### Configuration File

The configurator can also be configured using a YAML file. Here's an example configuration:

```yaml
api_url: "http://dns-server:5380"
api_token: "your-token"
username: "admin"
password: "your-password"
token_path: "/app/token.yaml"
timeout: 30s
log_level: "info"  # debug, info, warn, or error
k8s_secret_name: "technitium-token"
k8s_secret_namespace: "default"
k8s_secret_key: "api-token"
```

### Basic Usage

1. Create a token (using environment variables):
```bash
# Store token in a file
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="your-password" \
  -e DNS_TOKEN_PATH="/app/token.yaml" \
  -v "$(pwd)/token.yaml:/app/token.yaml" \
  ashtonian/technitium-configurator:latest create-token

# Store token in a Kubernetes secret
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="your-password" \
  -e DNS_K8S_SECRET_NAME="technitium-token" \
  -e DNS_K8S_SECRET_NAMESPACE="default" \
  ashtonian/technitium-configurator:latest create-token
```

1. Configure DNS server (using environment variables):
```bash
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_API_TOKEN="your-token" \
  -e DNS_CONFIG_PATH="/app/config.yaml" \
  -v "$(pwd)/config.yaml:/app/config.yaml" \
  ashtonian/technitium-configurator:latest configure
```

1. Change password:

```bash
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="current-password" \
  -e DNS_NEW_PASSWORD="new-password" \
  ashtonian/technitium-configurator:latest change-password
```

### Volume Mounts

You can mount your configuration files into the container:

- `config.yaml`: Mount to `/app/config.yaml` for DNS server configuration
- `token.yaml`: Mount to `/app/token.yaml` if using token file storage

Example with all files:

```bash
docker run --rm \
  -e DNS_CONFIG_PATH="/app/config.yaml" \
  -e DNS_TOKEN_PATH="/app/token.yaml" \
  -v "$(pwd)/config.yaml:/app/config.yaml" \
  -v "$(pwd)/token.yaml:/app/token.yaml" \
  ashtonian/technitium-configurator:latest configure
```

### Available Commands

```
configure <config.yaml>    Configure DNS server using the provided config file
create-token              Create an API token (saves to token.yaml if DNS_TOKEN_PATH is set)
change-password           Change the password for the current user
```

### Examples

See `examples` folder for `docker-compose.yaml` and `k8s.yaml`, as well as a configuration example `config.yaml`.

### Building

To build the Docker image locally:

```bash
docker build -t technitium-configurator .
```

## Limitations

### Zone Management

When re-running the configurator on existing zones:

1. **Cannot Change**:
   - Zone type (primary/secondary)
   - Zone name
   - Zone transfer protocol
   - TSIG key name

2. **Can Update**:
   - Records within the zone
   - Zone options (catalog, validation, etc.)
   - ACL settings

### App Management

- Apps are installed if not present
- App configurations are updated if changed
- Cannot uninstall apps through the configurator

### Token Management

- Creates non-expiring tokens
- Token can be stored in:
  - A file (if DNS_TOKEN_PATH is set)
  - A Kubernetes secret (if DNS_K8S_SECRET_NAME is set)
  - Displayed in logs only (if no storage is configured)
- Will not overwrite existing valid token if saving to file or secret
- Token must be manually deleted to create a new one when using file or secret storage
- When using Kubernetes secrets:
  - Secret will be created if it doesn't exist
  - Secret will be updated if it exists but doesn't contain a token
  - Operation will fail if secret exists and contains a valid token
  - Requires Kubernetes cluster access (in-cluster or kubeconfig)

### Logging

The configurator uses structured logging with the following levels:

- `debug`: Detailed information for debugging, including sensitive data like API tokens and passwords
- `info`: General operational information (default)
- `warn`: Warning messages for potentially harmful situations
- `error`: Error messages for serious problems

> **Warning**: Debug logging will include sensitive information such as API tokens and passwords. Use with caution in production environments.

The log level can be set via (in order of precedence):

1. Command line flag: `--log-level` (overrides all other settings)
2. Environment variable: `DNS_LOG_LEVEL`
3. Configuration file: `log_level` field
4. Default: `info` if not specified

Note: The application starts with debug logging enabled to help diagnose initialization issues, then switches to the configured level after loading the configuration.

Example setting log level:

```bash
# Via command line flag (highest precedence)
docker run --rm \
  --log-level debug \
  ashtonian/technitium-configurator:latest configure

# Via environment variable
docker run --rm \
  -e DNS_LOG_LEVEL="debug" \
  ashtonian/technitium-configurator:latest configure

# Via config file
log_level: "debug"  # in config.yaml
```

## Building

```bash
go build -o technitium-configurator
```

## Wishlist TODO:

* Better versioning/changelog
* Integration/Unit tests :see_no_evil:
* create/sync usernames + credentials
* All the apps
