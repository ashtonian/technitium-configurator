# Technitium Configurator

A Go tool for configuring Technitium DNS Server, supporting both one-time setup and continuous configuration management (see limitations).

## Features

- Create and manage API tokens
- Configure DNS server settings
- Manage DNS zones and records
- Install and configure apps

## Supported Apps

Currently supports:

- Blocking (DNS blocking and filtering)
- Forwarding (DNS forwarding and proxy)

### Adding New Apps

To add support for a new app:

1. Add a new config struct in `pkg/technitium/`, struct needs json and yaml tags.

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

### Running with Docker

The configurator is available as a Docker image:

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
```

### Basic Usage

1. Create a token (using environment variables):
```bash
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="your-password" \
  ashtonian/technitium-configurator:latest create-token
```

2. Configure DNS server (using environment variables):
```bash
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_API_TOKEN="your-token" \
  -e DNS_CONFIG_PATH="/app/config.yaml" \
  -v "$(pwd)/config.yaml:/app/config.yaml" \
  ashtonian/technitium-configurator:latest configure
```

3. Change password:
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
- Token can be:
  - Saved to a file (if DNS_TOKEN_PATH is set)
  - Displayed in logs only (if no token path provided)
- Will not overwrite existing valid token if saving to file
- Token must be manually deleted to create a new one when using file storage

## Building

```bash
go build -o technitium-configurator
```
