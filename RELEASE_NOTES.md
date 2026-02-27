# Release Notes — v2.0.0

## Highlights

This release brings **DNS cluster orchestration**, **Kubernetes-native token management**, a complete **credential system overhaul**, **end-to-end testing**, and significantly expanded DNS settings coverage. The configurator now supports the full Technitium DNS Server v14.x feature set including declarative cluster init/join with tunable timing options.

---

## New Features

### Cluster Support
- **Declarative cluster init/join** — Add a `cluster:` section to your DNS config YAML to initialize a primary or join a secondary to an existing cluster during `configure`
- **`cluster-state` command** — New standalone command to inspect cluster topology, node health, IP addresses, and uptime
- **Cluster timing options** — Tune `configRefreshIntervalSeconds`, `configRetryIntervalSeconds`, `heartbeatRefreshIntervalSeconds`, and `heartbeatRetryIntervalSeconds` on the primary node via `/api/admin/cluster/primary/setOptions`
- **2FA support** — `primaryTotp` field for joining clusters with TOTP-enabled primary nodes
- **Automatic re-authentication** — After cluster init/join the configurator waits for the server to stabilize and re-authenticates before continuing with DNS settings, zones, and records
- **Idempotent** — If the cluster is already initialized, the cluster step is skipped

### Kubernetes Integration
- **Token storage in K8s secrets** — `create-token` can now save API tokens directly to Kubernetes secrets (`DNS_K8S_SECRET_NAME`, `DNS_K8S_SECRET_NAMESPACE`, `DNS_K8S_SECRET_KEY`)
- **RBAC manifests** — Example K8s manifests include ServiceAccount, Role, and RoleBinding with minimal permissions
- **In-cluster and kubeconfig support** — Automatically detects cluster environment

### Credential Handling Overhaul
- **Unified `ClientConfig`** with environment variable support via struct tags
- **Dual auth** — API token (`DNS_API_TOKEN`) or username/password (`DNS_USERNAME`/`DNS_PASSWORD`)
- **Auto-login** — Client automatically authenticates with username/password when no token is provided
- **Config file + env vars** — YAML config with environment variable overrides (env takes precedence)
- **Configurable log level** — `DNS_LOG_LEVEL` (`debug`, `info`, `warn`, `error`)

### DNS Settings
- `defaultNsRecordTtl` — NS record TTL
- `defaultSoaRecordTtl` — SOA record TTL
- `loggingType` — Logging output type (e.g., `FileAndConsole`)
- 100+ total configurable DNS parameters

### Records
- **`name`/`value` aliases** — Use `name` instead of `domain` and `value` instead of `ipAddress` for A/AAAA records in YAML configs

### End-to-End Testing
- **Full lifecycle tests** — Spins up real Technitium DNS servers via Docker Compose
- **Idempotency verification** — Runs configure twice and verifies state is preserved
- **Cluster tests** — Primary init, secondary join, config replication, and idempotent re-runs
- **DNS settings verification** — Validates domain, TTL, serveStale, DoH, UDP payload size

---

## Bug Fixes

- Fixed API path for `AddRecord` (missing leading `/`)
- Fixed `FuzzyTime` JSON unmarshaling for zero-value timestamps
- Fixed app config struct tags for correct JSON serialization
- Fixed login flow to properly update client token on success
- Fixed zone options update to continue even when zone create fails (idempotent re-runs)
- Fixed ACL handling for zone transfer and update policies
- Fixed logging transport to properly redact sensitive tokens
- Fixed app default value handling for Advanced Blocking and Advanced Forwarding configs

---

## Improvements

- **Restructured project layout** — Commands moved to `cmd/commands.go`, client config to `pkg/technitium/client_config.go`
- **HTTP request/response logging** — Debug-level structured logging for all API calls with token redaction
- **Comprehensive examples** — `examples/config.yaml`, `examples/docker-compose.yaml`, `examples/k8s.yaml` with full cluster and DNS settings coverage
- **Multi-arch Docker images** — `linux/amd64` and `linux/arm64` via GitHub Actions with GHA build cache
- **Dockerfile optimized** — Multi-stage build with `alpine`, stripped binary (`-ldflags="-s -w"`)
- **CI/CD** — Automatic GitHub Releases with auto-generated or custom release notes on tag push

---

## Breaking Changes

- **`ClusterNode.IPAddress`** changed from `string` to `IPAddresses []string` (JSON: `ipAddresses`) — matches Technitium v14 API response
- **CLI interface** — Command-line argument parsing rewritten; commands are now positional (`configure`, `create-token`, `change-password`, `cluster-state`)
- **Config structure** — Old `pkg/config/config.go` replaced by `pkg/technitium/client_config.go` with env tag support
- **K8s examples** — Consolidated from `examples/k8s/` directory into single `examples/k8s.yaml`

---

## Compatibility

Tested against **Technitium DNS Server v14.x** (v14.3+). Cluster features require v14.0+. Older versions may work for basic DNS settings, zones, and records but are not officially supported.
