## v3.0.0

v3 targets Technitium DNS Server v15.6.0 and later and makes `configure` a dependable bootstrapper. The first run sets up a fresh server. Every later run succeeds without changing what is already there: records, apps, users, groups and permissions are compared with the server and only differences are sent, while settings and zone options are sent as before in one idempotent call each. Problems the tool can detect stop the run before anything changes. New in this release: record policies, `export`, config directories and multi-document files, and users, groups and permissions. Each release supports the current Technitium version only.

### Upgrading from v2

- **Technitium v15.6.0 or later is required.** v14 notes and legacy setting names are gone.
- **Config files are strict.** Unknown keys are errors, and the whole input is validated before any API call. Remove or rename obsolete keys:
  - `preferIPv6` → `ipv6Mode`
  - `enableLogging` → `loggingType`
  - `reverseProxyNetworkACL` → `dnsReverseProxyNetworkACL`
  - `qpmLimitRequests`, `qpmLimitErrors` → `qpmPrefixLimitsIPv4`, `qpmPrefixLimitsIPv6`
  - `cachePrefetchSample*` → `enableCachePrefetch`, `cachePrefetchTrigger`
- **Values the server used to accept or ignore are now errors.** Examples include zone ACL options it silently ignored, TSIG secrets that are not base64, malformed endpoints and forwarders, and TTLs above 2147483647. The error names the file and the field.
- **Record `overwrite` is replaced by `recordPolicy`.** Use `recordPolicy: replace` on the record, its zone or the whole file.
- **Client config and DNS config are separate files.** `--config` (or the new `DNS_CLIENT_CONFIG`) names a client config file holding connection and login settings only, as a single YAML document. It has no default, and a file named there must exist. The DNS config is the argument to `configure`, or `DNS_CONFIG_PATH`, or the new `config_path` key, then `config.yaml`.
- **Flags go after the command:** `technitium-configurator configure --log-level debug dns.yaml`.
- **Logs go to stderr.** stdout carries only command output, such as `export`'s YAML.
- **Exit codes.** `configure` exits `1` when any operation fails. A failure in a zone, record, app or administration item is logged and the rest is still attempted; a settings or cluster failure stops the run. Resources that already exist are skipped quietly instead of being logged as errors.
- **`create-token` needs a destination.** Set `DNS_TOKEN_PATH`, `DNS_K8S_SECRET_NAME` or both; a token that would only be logged is not created.
- **Typed app configs are removed.** An app's `config` is passed to the app as JSON. The Advanced Blocking and Advanced Forwarding models dropped fields and set `dnssecValidation: false` on forwarders. Give the app's complete config, as the app's own config page shows it.
- **The image is built `FROM scratch` and runs as user `65532`.** A file the tool creates, such as a new token file, needs a directory that user can write. An existing token file must be readable and writable by it, and either already mode `0600` or changeable to it.
- **Go module path is `github.com/ashtonian/technitium-configurator/v3`.** This only matters if you import `pkg/technitium`.

### New

- **Record policies.** `merge` (the default) adds missing values and keeps the rest, logging values the file does not list. `replace` makes the declared values the only ones for a name and type. Set the policy per file, per zone or per record. Both compare with the server first and send nothing when it already matches.
- **Exact record comparison.** Values are compared in the form the server stores them, and values the server keeps apart stay apart:
  - names in any case, IDN form or with a trailing dot;
  - IPv6 in any spelling, with or without brackets;
  - TXT by its character strings;
  - RP mailboxes in either form;
  - SVCB parameters by type, ignoring hints the server fills in;
  - FWD records by every field;
  - DS, SSHFP and TLSA values by name or number;
  - URIs as the server normalizes them, with escapes such as `%2F` kept distinct.
- **Checks before any change.** After the files are validated, the run places every record against the server's zones and checks the cluster timing options against the current ones before it changes anything. A record no zone contains or whose named zone does not exist, two values for a CNAME, DNAME or APP name, conflicting policies for one name and type, an FWD record outside a Forwarder zone, and timing options the server would reject stop the run. Problems only the server can find still fail during the run.
- **`export`** writes a running server's settings, zones, records, apps, groups, users and permissions as a DNS config file you can edit and apply again.
  - Applied to the same server, it changes nothing.
  - Applied to a fresh server, it reproduces what it holds once you add password sources for users and package URLs for apps outside the App Store. Cluster membership is set up separately.
  - It keeps the root zone, disabled zones, zones kept out of the cluster catalog, NS glue, TXT without strings, binary TXT, and exact app config numbers. Records the API cannot write back, such as a TXT record containing an empty character string, are skipped and named in the export's header.
  - It checks that its output loads before writing it.
  - User passwords, masked certificate passwords and everything the cluster owns are left out.
- **Several files, directories and documents.** `configure base.yaml zones/` merges every file, every `*.yaml` and `*.yml` in a directory, and every `---` document. Lists are combined. `recordPolicy`, `cluster` and each `dnsSettings` key may be set in only one place, and duplicate zones, apps, groups, users and TSIG keys are errors. Validation and record placement errors name the file and document they come from.
- **Administration.** Groups and users are created if absent; descriptions, display names, disabled state, session timeouts, group membership and section permissions are merged in.
  - Initial passwords come from `password`, `passwordFile` or `passwordEnv`, read only when the user is created.
  - Permissions naming an unknown user or group fail, because the server would drop them silently, and the run checks that the server kept every grant.
- **Every v15.6 server setting**: all 131 keys `/api/settings/set` accepts, including `enableCachePrefetch`, `ipv6Mode`, `noStackTrace`, `locallyServedDnsZones`, Unix socket options and the global proxy. Ranges, enums, formats and cross-field rules are checked before anything is sent.
- **Zones:** the root zone `.`, `disabled`, and catalog overrides (`overrideCatalogQueryAccess`, `overrideCatalogZoneTransfer`, `overrideCatalogNotify`). Overrides are never turned on implicitly, because on a cluster the catalog's zone transfer and notify settings are what replicate zones. A member zone that declares ACLs without the matching override gets a warning that they are not in effect.
- **Record types and fields.**
  - `characterStringsBase64` for byte-exact TXT.
  - `rdata` hex for other types the server knows by name (such as `HINFO`) or as `TYPE<number>`, except the types listed in the README as not declarable.
  - `svcParams` may be left out for an SVCB or HTTPS record without parameters.
- **Apps.** `url` is needed only when the app has to be installed. In `config`, YAML merge keys are resolved, duplicate keys and recursive aliases are errors, and numbers keep every digit.
- **Clusters.**
  - Node IPs are updated when `nodeIPs` changes after init or join.
  - `primaryTotp` is passed on the join and on the login right after it. Later runs need a primary user without two-factor authentication.
- **`version`** prints the version, commit and build date.
- **`DNS_WAIT_TIMEOUT`** (default `60s`): commands wait for the server's `/api/status` before starting, and settings that restart the web service (including HTTP/3) wait for it to come back.
- **`cluster-state`** shows each node's version and last config sync.

### Fixes

- Settings send explicit `false`, `0`, `""` and `[]`. Before, these values were silently dropped, so defaults such as `dnssecValidation`, `serveStale`, `enableBlocking` or `cacheMaximumEntries` could not be changed.
- Record `ttl`, `comments` and `expiryTtl` are applied. They were discarded when the YAML was read, so every record got the server's default TTL.
- Re-runs no longer send every record again. A 3,000-record config re-applied in 15 requests (0.34 s) instead of 3,011, with no record writes.
- `ptr: true` no longer overwrites a PTR record that already exists with another value, under `merge`. The conflict is reported instead.
- Zones created on a cluster primary join the cluster catalog and replicate to secondaries.
- A secondary that has joined a cluster can re-run its config. After a join, the node has the primary's users and drops its own API tokens (tokens are not copied between nodes), so when the configured token or login fails, the run logs in with `primaryUsername` and `primaryPassword`.
- TSIG keys in `dnsSettings` are merged with the server's, so the cluster's key survives a settings change. Key names are compared case-insensitively and without the trailing dot.
- An explicit empty ACL list, such as `updateNetworkACL: []`, clears it.
- `change-password` succeeds on re-run once the new password works.
- `create-token` checks a stored token with the server and replaces it when it is no longer valid, for example after the server was redeployed with fresh storage. A configured `DNS_API_TOKEN` is checked before use.
- Cluster timing options are applied on every run on the primary, including when authenticating with an API token.
- Apps that are already installed are not downloaded again. App config is written only when it differs from the stored config, ignoring comments and formatting.
- CNAME, DNAME and APP records that exist with another value are reported as conflicts instead of failures.
- The linux/arm64 image contains an arm64 binary (#4).
- The examples run in a working order. Compose runs the configurator steps in sequence and sets `DNS_SERVER_ADMIN_PASSWORD`, the variable the server reads. Kubernetes changes the password before creating a token, and its RBAC is limited to reading and updating the token Secret, plus creating Secrets, which Kubernetes cannot limit by name. DNS-over-QUIC is opt-in in the example config, since it needs `libmsquic` on the server.

### Security

- Passwords and tokens no longer reach logs or error messages (#3). Logins and password changes are POST requests with credentials in the body, the token is sent as an `Authorization: Bearer` header, request and response bodies are never logged, and connection errors name the API path instead of the full URL. Conflict messages leave out APP record data and proxy passwords.
- `DNS_API_URL` may not contain credentials, a query or a fragment, and redirects are refused rather than followed with the token.
- Token and export files are made mode `0600` before anything is written. A token file is replaced atomically when its directory is writable, and otherwise overwritten in place only if it can be made private.
- `golang.org/x/net` v0.61.0 and `golang.org/x/text` v0.43.0 clear the advisories govulncheck reported.

### Build and release

- Multi-arch image `FROM scratch` with CA certificates only, run as a non-root user, with build provenance and an SBOM. Builds are reproducible: pinned base images, `-trimpath`, no build ID.
- CI runs vet, golangci-lint (e2e code included), race-enabled unit tests, govulncheck and e2e tests against Technitium 15.6.1 (single node and cluster) before building. The e2e tests fail, not skip, without Docker.
- Each platform's binary is built and checked for its architecture and version before any image is pushed.
- `latest` is tagged for stable releases only, and a release publishes only its own section of these notes. Tags with a suffix, such as `v3.0.0-rc.1`, are published as prereleases.

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
