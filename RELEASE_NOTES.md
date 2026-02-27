## v2.0.0

v2.0 is a major release that adds DNS cluster orchestration, a comprehensive DNS settings API, a new CLI architecture, Kubernetes secret management, end-to-end tests, and numerous bug fixes.

### Cluster Support

- **Primary mode** — initialize a cluster with `cluster.mode: "primary"`, specifying domain and node IPs. DNS settings, zones, and records are configured on the primary and replicate automatically.
- **Secondary mode** — join an existing cluster with `cluster.mode: "secondary"`, pointing at the primary URL/IP with credentials (including optional TOTP for 2FA-enabled primaries).
- **Cluster timing options** — configurable `configRefreshIntervalSeconds`, `configRetryIntervalSeconds`, `heartbeatRefreshIntervalSeconds`, and `heartbeatRetryIntervalSeconds` on the primary.
- **`cluster-state` command** — inspect cluster topology, node connectivity, and timing configuration.
- TSIG keys from cluster init are preserved and merged with user-defined DNS settings.

### DNS Settings

- Full coverage of Technitium DNS server settings (60+ parameters): server domain, endpoints, TTL defaults, recursion policies, DNSSEC validation, TSIG keys, caching, query rate limiting, logging, and all protocol toggles (UDP, TCP, TLS, HTTPS, HTTP/3, QUIC).
- Fixed form-encoded POST for `SetDNSSettings` to match the Technitium API contract.

### CLI Refactor

- Replaced the monolithic `main.go` with a command registry (`cmd/commands.go`). Commands are now modular and self-describing.
- New commands: **`configure`**, **`create-token`**, **`change-password`**, **`cluster-state`**.
- Unified configuration loading: YAML file → environment variables → CLI flags, with clear precedence.
- New `--config`, `--token-path`, and `--log-level` root flags.
- Expanded environment variable support: `DNS_API_URL`, `DNS_API_TOKEN`, `DNS_USERNAME`, `DNS_PASSWORD`, `DNS_NEW_PASSWORD`, `DNS_CONFIG_PATH`, `DNS_TOKEN_PATH`, `DNS_TIMEOUT`, `DNS_LOG_LEVEL`, `DNS_K8S_SECRET_NAME`, `DNS_K8S_SECRET_NAMESPACE`, `DNS_K8S_SECRET_KEY`.

### Kubernetes Integration

- **Token storage in K8s secrets** — `create-token` can persist API tokens to a Kubernetes secret (`DNS_K8S_SECRET_NAME`), with configurable namespace and key.
- Singleton K8s client with automatic in-cluster / kubeconfig detection.
- Atomic secret updates with optimistic locking for concurrent safety.

### Record Handling

- **Field aliases** — records accept `name` for `domain` and `value` for `ipAddress`/`exchange`/`cname`/etc., making configs more intuitive.
- Full support for all 18+ record types: A, AAAA, NS, CNAME, PTR, MX, TXT, SRV, DNAME, DS, SSHFP, TLSA, SVCB, HTTPS, URI, CAA, ANAME, NAPTR, FWD, APP.

### Zone & ACL Improvements

- ACL settings per zone: `queryAccess`, `zoneTransfer`, `notify`, `update` with TSIG-aware policies.
- Zone creation retry logic with back-off for transient failures.
- Continue applying zone settings even when zone already exists.

### App Configuration

- **Advanced Blocking** — network group mapping, per-group block/allow lists (URL and regex), adblock format, custom blocking addresses, NXDOMAIN mode.
- **Advanced Forwarding** — named forwarders with protocol selection, SOCKS5/HTTP proxy support, network group routing, domain-specific forwarding, Adguard upstream config files.

### Error Handling & Logging

- Parse `errorMessage` from Technitium API JSON responses for actionable error output.
- Structured `slog`-based logging with configurable level (`debug`, `info`, `warn`, `error`).
- Full HTTP request/response logging with token redaction.
- Source file and line numbers in debug-level logs.

### End-to-End Tests

- `TestE2EIdempotency` — full lifecycle: password change → token creation → configure → re-run idempotency verification against a real Technitium container.
- `TestE2ECluster` — primary/secondary cluster setup with replication, zone/record propagation, and timing option verification.
- Docker Compose test harnesses for single-node and cluster topologies.

### Examples & Documentation

- Comprehensive example config (`examples/config.yaml`) covering all features.
- Docker Compose examples for standalone and cluster deployments (`examples/docker-compose.yaml`).
- Unified Kubernetes manifests with ConfigMap, ExternalSecret, Job, and RBAC (`examples/k8s.yaml`).
- Expanded README with full configuration reference.

### Build & Dependencies

- Go 1.24.2 → 1.26.0
- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go`: v0.33.1 → v0.35.1
- `google.golang.org/protobuf`: v1.36.5 → v1.36.11
- `golang.org/x/net`: v0.38.0 → v0.51.0
- `golang.org/x/sys`: v0.31.0 → v0.41.0
- `github.com/google/go-querystring`: v1.1.0 → v1.2.0
- `sigs.k8s.io/yaml`: v1.4.0 → v1.6.0
- CI: `actions/checkout` v4 → v6, `docker/build-push-action` v5 → v6
- Added `LICENSE` (MIT)
- Added `.github/release.yml` for automated release notes

### Bug Fixes

- Fixed credential handling for token vs username/password authentication flows.
- Fixed login failures when token is absent and username/password fallback is needed.
- Fixed app config struct tags preventing correct YAML unmarshaling.
- Fixed DNS settings not being applied when app install fails.
- Fixed default app config values not being set correctly.
- Fixed logging output missing structured fields.

---

## v1.0.0

Initial release with declarative DNS configuration: zones, records, apps (Advanced Blocking, Advanced Forwarding), and basic `configure` / `create-token` commands.
