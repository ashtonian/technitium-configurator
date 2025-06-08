# Technitium Configurator

A Go tool for configuring Technitium DNS Server, supporting both one-time setup and continuous configuration management.

## Features

- Create and manage API tokens
- Configure DNS server settings
- Manage DNS zones and records
- Install and configure apps
- Kubernetes-ready with init container support

## Supported Apps

Currently supports:
- Blocking (DNS blocking and filtering)
- Forwarding (DNS forwarding and proxy)

### Adding New Apps

To add support for a new app:

1. Add a new config struct in `pkg/technitium/`, struct needs json and yaml tags.

2. Add a case in the app configuration switch statement in `main.go`:
```go
switch app.Name {
case "blocking":
    // existing blocking config
case "forwarding":
    // existing forwarding config
case "new-app":
    // handle new app config
}
```

## Usage

### Basic Usage

1. Create a token:
```bash
export DNS_API_URL="http://your-dns-server:5380"
export DNS_USERNAME="admin"
export DNS_PASSWORD="your-password"
./technitium-configurator create-token
```

2. Configure DNS server:
```bash
export DNS_API_URL="http://your-dns-server:5380"
./technitium-configurator configure config.yaml
```

### Example Config

```yaml
dns_settings:
  recursion: true
  recursion_allow_private: true

zones:
  - zone: example.com
    type: primary
    records:
      - domain: www.example.com
        type: A
        ip_address: 192.168.1.1

apps:
  - name: blocking
    url: https://github.com/TechnitiumSoftware/DnsServer/raw/master/BlockingApp.zip
    config:
      block_list_urls:
        - https://example.com/blocklist.txt
```

### Kubernetes Deployment

See `examples/k8s/` for a complete Kubernetes deployment example.

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
- Will not overwrite existing valid token in `token.yaml`
- Token must be manually deleted to create a new one

## Building

```bash
go build -o technitium-configurator
```

## License

MIT
