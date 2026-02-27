# Technitium Configurator

A Go tool for configuring [Technitium DNS](https://technitium.com/dns/) Server in a declarative fashion, supporting both one-time setup and continuous configuration management. Also supports password management, API token creation with Kubernetes secret sync, and DNS cluster orchestration.

## Why

DNS is *critical* and therefore its configuration should be easily repeatable. Technitium is one of the only open source, authoritative DNS servers with a UI that supports additional feature sets like DNS sinkhole, RFC 2136 (external-dns), split horizon, and more. However its config files are stored in binary with complex versioning/logic, and there isn't a declarative solution. To address this, an over-engineered configuration utility was born.

## Features

- **Declarative DNS configuration** — define your entire DNS setup in YAML
- **DNS server settings** — 100+ configurable parameters
- **Zone management** — Primary, Secondary, Stub, Forwarder, Catalog zones with ACLs
- **Record management** — All standard record types (A, AAAA, CNAME, MX, TXT, SRV, DS, SSHFP, TLSA, SVCB, HTTPS, URI, CAA, NAPTR, FWD, APP, and more)
- **App installation & configuration** — Advanced Blocking, Advanced Forwarding
- **Cluster support** — Initialize, join, and inspect Technitium DNS clusters
- **API token management** — Create non-expiring tokens, store in file or Kubernetes secret
- **Password management** — Change user passwords
- **Kubernetes-native** — Token storage in K8s secrets, RBAC manifests, Job-based deployment
- **Idempotent** — Safe to run repeatedly; existing state is detected and preserved

## Available Commands

| Command | Description |
|---|---|
| `configure` | Apply DNS server configuration from a YAML file |
| `create-token` | Create an API token (saves to file and/or Kubernetes secret) |
| `change-password` | Change the password for the current user |
| `cluster-init` | Initialize clustering on the primary node |
| `cluster-join` | Join this node to an existing cluster as secondary |
| `cluster-state` | Display the current cluster topology and health |

## Quick Start

### Running as a Container

```bash
docker pull ashtonian/technitium-configurator:latest
```

Multi-arch images are published for `linux/amd64` and `linux/arm64`.

### 1. Change the Default Password

```bash
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="admin" \
  -e DNS_NEW_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:latest change-password
```

### 2. Create an API Token

```bash
# Save token to a file
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  -e DNS_TOKEN_PATH="/app/token.yaml" \
  -v "$(pwd)/token.yaml:/app/token.yaml" \
  ashtonian/technitium-configurator:latest create-token

# Or save token to a Kubernetes secret
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  -e DNS_K8S_SECRET_NAME="technitium-token" \
  -e DNS_K8S_SECRET_NAMESPACE="default" \
  ashtonian/technitium-configurator:latest create-token
```

### 3. Apply DNS Configuration

```bash
docker run --rm \
  -e DNS_API_URL="http://your-dns-server:5380" \
  -e DNS_API_TOKEN="your-token" \
  -e DNS_CONFIG_PATH="/app/config.yaml" \
  -v "$(pwd)/config.yaml:/app/config.yaml" \
  ashtonian/technitium-configurator:latest configure
```

### 4. Set Up a Cluster

```bash
# Initialize the primary node
docker run --rm \
  -e DNS_API_URL="http://primary-dns:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="password" \
  -e DNS_CLUSTER_DOMAIN="dns-cluster.example.com" \
  -e DNS_CLUSTER_NODE_IPS="10.0.0.1,10.0.0.2" \
  ashtonian/technitium-configurator:latest cluster-init

# Join a secondary node
docker run --rm \
  -e DNS_API_URL="http://secondary-dns:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="password" \
  -e DNS_CLUSTER_NODE_IPS="10.0.0.2" \
  -e DNS_CLUSTER_PRIMARY_URL="https://primary-dns:5380" \
  -e DNS_CLUSTER_PRIMARY_IP="10.0.0.1" \
  -e DNS_CLUSTER_PRIMARY_USERNAME="admin" \
  -e DNS_CLUSTER_PRIMARY_PASSWORD="password" \
  ashtonian/technitium-configurator:latest cluster-join

# Check cluster state
docker run --rm \
  -e DNS_API_URL="http://primary-dns:5380" \
  -e DNS_API_TOKEN="your-token" \
  ashtonian/technitium-configurator:latest cluster-state
```

## Configuration

The configurator supports two methods of configuration, with environment variables taking precedence over YAML:

1. **Environment Variables** — all settings can be provided via env vars, no config files required
2. **YAML Configuration Files** — traditional file-based configuration, can be mixed with env vars

### Environment Variables

#### Connection & Auth
| Variable | Required | Description |
|---|---|---|
| `DNS_API_URL` | Yes | URL of the DNS server API (e.g., `http://dns-server:5380`) |
| `DNS_API_TOKEN` | Conditional | API token for authentication |
| `DNS_USERNAME` | Conditional | Username for token creation, password change, and cluster commands |
| `DNS_PASSWORD` | Conditional | Current password |
| `DNS_NEW_PASSWORD` | For `change-password` | New password |

#### Paths & Behavior
| Variable | Default | Description |
|---|---|---|
| `DNS_CONFIG_PATH` | `config.yaml` | Path to DNS configuration file |
| `DNS_TOKEN_PATH` | | Path to token file output |
| `DNS_TIMEOUT` | `30s` | API call timeout |
| `DNS_LOG_LEVEL` | `info` | Logging level: `debug`, `info`, `warn`, `error` |

#### Kubernetes
| Variable | Default | Description |
|---|---|---|
| `DNS_K8S_SECRET_NAME` | | Name of Kubernetes secret to store token in |
| `DNS_K8S_SECRET_NAMESPACE` | `default` | Namespace for the Kubernetes secret |
| `DNS_K8S_SECRET_KEY` | `api-token` | Key in Kubernetes secret to store token |

#### Clustering
| Variable | Description |
|---|---|
| `DNS_CLUSTER_DOMAIN` | Cluster domain name (required for `cluster-init`) |
| `DNS_CLUSTER_NODE_IPS` | Comma-separated node IPs (required for `cluster-init` and `cluster-join`) |
| `DNS_CLUSTER_PRIMARY_URL` | Primary node URL (required for `cluster-join`) |
| `DNS_CLUSTER_PRIMARY_IP` | Primary node IP (for `cluster-join`) |
| `DNS_CLUSTER_PRIMARY_USERNAME` | Primary node username (required for `cluster-join`) |
| `DNS_CLUSTER_PRIMARY_PASSWORD` | Primary node password (required for `cluster-join`) |
| `DNS_CLUSTER_IGNORE_CERT_ERRORS` | Skip TLS verification for cluster communication |

### Configurator Config File

The configurator itself can be configured via YAML (separate from the DNS config):

```yaml
api_url: "http://dns-server:5380"
api_token: "your-token"
username: "admin"
password: "your-password"
token_path: "/app/token.yaml"
timeout: 30s
log_level: "info"
k8s_secret_name: "technitium-token"
k8s_secret_namespace: "default"
k8s_secret_key: "api-token"
cluster_domain: "dns-cluster.example.com"
cluster_node_ips: "10.0.0.1,10.0.0.2"
```

### DNS Configuration File

The DNS config file defines your desired server state. See [`examples/config.yaml`](examples/config.yaml) for a full reference.

```yaml
dnsSettings:
  dnsServerDomain: "technitium.somedomain.com"
  recursion: Deny
  logQueries: false
  loggingType: FileAndConsole
  useLocalTime: true
  maxLogFileDays: 7
  maxStatFileDays: 365
  qpmLimitRequests: 0
  qpmLimitErrors: 0
  enableDnsOverUdpProxy:  true
  enableDnsOverTcpProxy:  true
  enableDnsOverHttp:      true
  enableDnsOverTls:       true
  enableDnsOverHttps:     true
  enableDnsOverHttp3:     true
  enableDnsOverQuic:      true
  udpPayloadSize:         1232
  resolverConcurrency:    4
  forwarderConcurrency:   10
  forwarderTimeout:       2000
  forwarderRetries:       2
  concurrentForwarding:   true
  cacheMaximumEntries:    0
  serveStale:             true
  serveStaleTtl:          86400
  cacheNegativeRecordTtl: 60
  tsigKeys:
    - keyName: "external-dns"
      algorithmName: "hmac-sha256"
      sharedSecret: "somesecret"

zones:
  - zone:  "somedomain.com"
    type:  "Forwarder"
    initializeForwarder: true
    protocol: "Udp"
    forwarder: "172.0.0.1"
    dnssecValidation: false
    aclSettings:
      queryAccess: AllowOnlyPrivateNetworks
      zoneTransfer: UseSpecifiedNetworkACL
      zoneTransferNetworkACL: ["172.0.0.0/8"]
      zoneTransferTsigKeyNames: ["external-dns"]
      update: "UseSpecifiedNetworkACL"
      updateNetworkACL:
        - "172.0.0.0/8"
      updateSecurityPolicies: >
        external-dns|*.somedomain.com|ANY
        |external-dns|somedomain.com|ANY

  - zone:  "someotherdomain.com"
    type:  "Forwarder"
    initializeForwarder: true
    protocol: "Https"
    forwarder: "https://cloudflare-dns.com/dns-query"
    dnssecValidation: true

records:
  - domain: "www.somedomain.com"   # or use "name" as alias
    type: "A"
    ttl: 3600
    ipAddress: "192.168.1.1"       # or use "value" as alias for A/AAAA
    ptr: true

  - domain: "mail.somedomain.com"
    type: "MX"
    ttl: 3600
    exchange: "mail.somedomain.com"
    preference: 10

  - domain: "somedomain.com"
    type: "TXT"
    ttl: 3600
    text: "v=spf1 ip4:192.168.1.1 -all"

apps:
  - name: "Advanced Blocking"
    url: "https://download.technitium.com/dns/apps/AdvancedBlockingApp-v8.zip"
    config:
      enableBlocking: true
      blockListUrlUpdateIntervalHours: 24
      networkGroupMap:
        "0.0.0.0/0":      "home"
        "::/0":           "home"
      groups:
        - name: home
          enableBlocking: true
          allowTxtBlockingReport: true
          blockAsNxDomain: true
          blockingAddresses: [ "0.0.0.0", "::" ]
          allowed: []
          blocked: []
          allowListUrls: []
          allowedRegex: []
          blockedRegex: []
          regexAllowListUrls: []
          regexBlockListUrls: []
          adblockListUrls: []
          blockListUrls:
            - "https://raw.githubusercontent.com/xRuffKez/NRD/refs/heads/main/lists/14-day/wildcard/nrd-14day_wildcard.txt"
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt"
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt"
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nosafesearch-onlydomains.txt"
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt"

  - name: "Advanced Forwarding"
    url:  "https://download.technitium.com/dns/apps/AdvancedForwardingApp-v3.1.zip"
    config:
      enableForwarding: true
      forwarders:
        - name: "opendns"
          dnssecValidation: true
          forwarderProtocol: "Https"
          forwarderAddresses:
            - "https://doh.opendns.com/dns-query"
        - name: "cloudflare"
          dnssecValidation: true
          forwarderProtocol: "Tls"
          forwarderAddresses:
            - "tls://1.1.1.1"
            - "tls://1.0.0.1"
        - name: "quad9"
          dnssecValidation: true
          forwarderProtocol: "Https"
          forwarderAddresses:
            - "https://dns.quad9.net/dns-query"
      networkGroupMap:
        "0.0.0.0/0": "default"
        "::/0":      "default"
      groups:
        - name: "default"
          enableForwarding: true
          forwardings:
            - forwarders: ["opendns", "cloudflare", "quad9"]
              domains: ["*"]
```

### Supported Record Types

A, AAAA, NS, CNAME, PTR, MX, TXT, SRV, DNAME, DS, SSHFP, TLSA, SVCB, HTTPS, URI, CAA, ANAME, NAPTR, FWD, APP

Records support aliases for convenience: `name` can be used instead of `domain`, and `value` instead of `ipAddress` for A/AAAA records.

### Supported Zone Types

Primary, Secondary, Stub, Forwarder, SecondaryForwarder, Catalog, SecondaryCatalog

Zone transfer protocols: TCP, TLS, QUIC

## Supported Apps

### Advanced Blocking

DNS-level ad/malware blocking with:
- Network group mapping (IPv4/IPv6 CIDR)
- Per-group block/allow lists (URLs and regex)
- Adblock-format list support
- Custom blocking addresses

### Advanced Forwarding

DNS forwarding with:
- Named forwarders with protocol selection (UDP, TCP, TLS, HTTPS, QUIC)
- SOCKS5/HTTP proxy support per forwarder
- Network group routing
- Domain-specific forwarding rules
- Adguard upstream support

### Adding New Apps

To add support for a new Technitium app:

1. Add a config struct in `pkg/technitium/` with json and yaml tags. The `UnmarshalYAML` and struct tags should account for any default value handling the app expects.

2. Add a case in the app configuration switch in `pkg/technitium/apps.go`:

```go
switch a.Name {
case "Advanced Blocking":
    cfg = new(BlockingConfig)
case "New App":
    cfg = new(NewAppConfig)
}
```

## Deployment

### Docker Compose

See [`examples/docker-compose.yaml`](examples/docker-compose.yaml) for a complete setup with DNS server and configurator containers.

### Kubernetes

See [`examples/k8s.yaml`](examples/k8s.yaml) for a complete K8s deployment including:
- ConfigMap for DNS configuration
- ExternalSecret for credentials
- Job with init containers for token creation, password change, and configuration
- RBAC (Role, RoleBinding, ServiceAccount) with minimal permissions

### Volume Mounts

Mount configuration files into the container:

- `config.yaml` → `/app/config.yaml` for DNS server configuration
- `token.yaml` → `/app/token.yaml` if using token file storage

## Building

### Binary

```bash
go build -o technitium-configurator
```

### Docker

```bash
docker build -t technitium-configurator .
```

Multi-arch builds (amd64/arm64) are automated via GitHub Actions on push to `main` and tag pushes.

## Testing

End-to-end tests spin up a real Technitium DNS server via Docker and verify the full configurator lifecycle including idempotency:

```bash
go test -tags=e2e ./e2e
```

Requires Docker to be available.

## Limitations

### Zone Management

When re-running the configurator on existing zones:

- **Cannot change**: zone type, zone name, zone transfer protocol, TSIG key name
- **Can update**: records, zone options (catalog, validation, etc.), ACL settings

### App Management

- Apps are installed if not present
- App configurations are updated if changed
- Cannot uninstall apps through the configurator

### Token Management

- Creates non-expiring tokens
- Idempotent — will not overwrite an existing valid token in file or Kubernetes secret
- Token can be stored in a file (DNS_TOKEN_PATH), a Kubernetes secret (DNS_K8S_SECRET_NAME), or displayed in logs only
- When using Kubernetes secrets: requires cluster access (in-cluster or kubeconfig)

### Logging

Structured logging with four levels: `debug`, `info`, `warn`, `error`.

Log level precedence (highest to lowest):
1. CLI flag: `--log-level`
2. Environment variable: `DNS_LOG_LEVEL`
3. Config file: `log_level`
4. Default: `info`

> **Warning**: Debug logging includes sensitive information such as API tokens and passwords. Use with caution in production environments.
