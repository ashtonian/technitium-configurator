# Compatibility

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Limitations](#limitations)
- [External dependencies](#external-dependencies)
- [Interfaces](#interfaces)

Requires **Technitium DNS Server v15.6.0 or later**. The e2e suite pins `technitium/dns-server:15.6.1`. Releases roll forward with the server; older servers are not supported. Every node of a cluster must run the same version.

Setting names follow the current server API. Legacy names the server still accepts are not part of the schema:

| Legacy key | Use instead |
|---|---|
| `preferIPv6` | `ipv6Mode` (`Disabled`, `Enabled` or `Preferred`) |
| `enableLogging` | `loggingType` (`None`, `File`, `Console` or `FileAndConsole`) |
| `reverseProxyNetworkACL` | `dnsReverseProxyNetworkACL` |
| `cachePrefetchSampleIntervalInMinutes`, `cachePrefetchSampleEligibilityHitsPerHour` | Removed with Auto Prefetch; use `enableCachePrefetch` and `cachePrefetchTrigger` |
| `qpmLimitRequests`, `qpmLimitErrors` | `qpmPrefixLimitsIPv4` and `qpmPrefixLimitsIPv6` |
| record `overwrite: true` | `recordPolicy: replace` |

## Limitations

- Nothing is pruned: zones, records, apps, groups, users and TSIG keys removed from the file stay on the server. Only `recordPolicy: replace` removes values, and only for the names and types the file declares.
- A zone that exists with a different type is reported, not converted.
- Apps are not upgraded or uninstalled.
- Cluster topology is set once; leaving, removing and promoting nodes are not managed.
- Settings are not transactional: the server applies them in order and keeps earlier ones when a later one fails. Validation catches the values it can know are wrong; one the server rejects for its own reasons, such as QUIC without `libmsquic`, can still leave earlier settings applied.
- Not managed: per-zone permissions, DNSSEC signing, allowed and blocked domain lists, DHCP, SSO, LDAP.

## External dependencies

| Dependency | Used for | Notes |
|---|---|---|
| Technitium DNS Server v15.6+ | Everything, through its HTTP API | Reachable at `DNS_API_URL` |
| Technitium App Store (`download.technitium.com`) | App packages and the store catalogue, fetched **by the DNS server** | When an app must be installed, and during `export`, which looks up each app's package URL |
| Kubernetes API | `create-token` storing the token in a Secret | Only when `DNS_K8S_SECRET_NAME` is set |
| Docker | The e2e test suite | Development only |

## Interfaces

- **CLI** — the [commands, flags and environment variables](cli-reference.md), and [exit codes](run-semantics.md#exit-codes).
- **DNS config schema** — the [YAML configuration schema](configuration.md), versioned with the major version (v3).
- **Go module** — `github.com/ashtonian/technitium-configurator/v3`. `pkg/technitium` is a typed client for the Technitium API and the config model; it follows the CLI's major version but is not otherwise a stable library API.
