# Technitium Configurator

[![Build](https://github.com/ashtonian/technitium-configurator/actions/workflows/docker.yml/badge.svg)](https://github.com/ashtonian/technitium-configurator/actions/workflows/docker.yml)
[![Docker Image](https://img.shields.io/docker/v/ashtonian/technitium-configurator?sort=semver&label=docker)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Docker Pulls](https://img.shields.io/docker/pulls/ashtonian/technitium-configurator)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Docker Image Size](https://img.shields.io/docker/image-size/ashtonian/technitium-configurator/latest)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ashtonian/technitium-configurator)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Technitium Configurator sets up a [Technitium DNS Server](https://technitium.com/dns/) from YAML files. Run it against a fresh server to configure it, then run it again as often as you like: it creates what is missing, applies the settings you list, and leaves everything else alone.

It also changes the admin password, creates API tokens (stored in a file or a Kubernetes Secret), initializes or joins DNS clusters, and exports a running server's configuration as YAML.

## Overview

DNS is critical, so its configuration should be repeatable. Technitium stores its configuration in binary files, and there is no declarative way to manage it; this tool fills that gap through Technitium's HTTP API.

- **Bootstrap, then re-run safely.** Zones, records, apps, groups and users are created when absent. Settings, zone options and the primary's cluster timing options are sent on every run; app config is written when it differs. Nothing is pruned: what the file leaves out stays on the server.
- **Every v15.6 server setting.** All 131 keys `/api/settings/set` accepts. Explicit `false`, `0`, `""` and `[]` are applied.
- **Zones and records.** All zone types, including the root zone, with ACLs, update policies and catalog membership. Every record type the API has fields for, and other types as hex RDATA, with a [record policy](#record-policies) that chooses between adding values and replacing them. See [Records](#records) for the types that cannot be declared.
- **Any DNS App.** Install from a package URL and pass its config through as JSON.
- **Clusters.** Initialize a primary or join a secondary; zones on the primary replicate through the cluster catalog.
- **Users, groups and permissions**, created if absent and merged into the existing grants.
- **Export.** Write a server's configuration as a config file you can edit and apply again.
- **Strict and honest.** Unknown keys and invalid values fail before any change. Existing resources are skipped quietly; real failures make the run exit non-zero.
- **Quiet re-runs.** Records, apps, users, groups and permissions are compared with the server in the form it stores them, and nothing that matches is sent again.

## Compatibility

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

## What a run does

| Section | Every run | When it already exists |
|---|---|---|
| `dnsSettings` | Sends exactly the keys in the file, on every run. Keys you leave out are not sent; a few settings that the server treats as a unit are reset together (see [Settings](#settings)) | — |
| `zones` | Creates missing zones, then sends their options and ACLs, on every run | Creation is skipped; options are still sent. A zone of a different type is reported as a conflict and left alone |
| `records` | Adds missing values (see [record policies](#record-policies)) | An identical record is not sent again; values are compared in the form the server stores them |
| `apps` | Installs missing apps; writes `config` when it differs from the stored config | Installation is skipped. Leave `config` out to keep the app's own |
| `administration` | Creates missing groups and users; applies descriptions, display names, disabled state, session timeouts, group membership and permissions | Membership and permissions are merged: groups and grants the file does not name are kept. Passwords are only set when a user is created |
| `cluster` | Applies the node IPs and the primary's timing options | Initialization or join happens once |

Nothing is pruned. Removing a zone, record, app, group or user from the file leaves it on the server. The one exception is `recordPolicy: replace`, which removes the other values of a name and type the file declares.

Settings and zone options are sent on every run because the server applies them in one idempotent call each; a re-run that sends them changes nothing. Everything else is compared first, and an unchanged re-run writes no record, zone, app, user, group or permission.

Checks happen in three stages:

1. **Loading the files.** Everything that can be judged from the files alone is checked. A YAML syntax error or a key set in two files stops loading at once; after that, every validation problem is reported together.
2. **Before any change.** The run reads the server's zones and places every record. A record no zone contains, a record naming a zone that does not exist, two values for a CNAME, DNAME or APP name, records of one name and type with different policies, an FWD record outside a Forwarder zone, and cluster timing options the server would reject all stop the run with nothing changed.
3. **During the run.** Some problems only the server can find, such as an app config the app rejects, a missing reverse zone for `ptr: true`, or QUIC without `libmsquic`. These fail that item, or stop the run when they happen in settings or the cluster.

The order is fixed: settings, cluster, administration, zones (catalog zones first), FWD records, apps, then the other records. FWD records come before apps because they decide how the server resolves the App Store's address; the other records come last so that a record can refer to an app or zone declared in the same file.

### Record policies

`recordPolicy` decides what happens when a name and type already have values on the server. Set it for the whole file, override it per zone, and override that per record.

| Policy | The file declares `www A 192.0.2.2`; the server has `192.0.2.1` | Use it for |
|---|---|---|
| `merge` (default) | Adds `192.0.2.2`. The server answers with both, and the run logs that `192.0.2.1` is not in the file | Zones you share with other writers, such as external-dns, DHCP or the web console |
| `replace` | The server ends up with only `192.0.2.2` | Names the file owns completely |

Under `merge`, a CNAME, DNAME or APP record that exists with a different value is reported as a conflict and left alone, because a name can hold only one of them. A PTR created by an earlier run or by hand is never overwritten under `merge`. The TTL, comments and expiry of a value that already exists are not changed.

Under `replace`, the declared values are compared with the server first, and nothing is written when they already match, including the TTL, comments, expiry TTL and NS glue the file sets. When they differ, the set is rewritten, `ptr: true` included. A name with several values briefly has fewer while the run writes them.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, or help was asked for (`help`, `--help`, `<command> --help`). Conflicts are logged as warnings and do not change the code |
| `1` | The config is invalid, a prerequisite (settings, cluster, login) failed, or at least one operation failed. The run continues past individual failures and lists every one at the end |
| `2` | Bad command-line usage: no command, an unknown command, an unknown flag, or too many arguments (`version` and `help` take none). The error and the usage text go to stderr |

## Commands

| Command | Description |
|---|---|
| `configure [path...]` | Apply DNS config files. A path may be a file or a directory (its `*.yaml` and `*.yml` files, in name order). Without a path, `DNS_CONFIG_PATH` is used, then the client config file's `config_path`, then `config.yaml` |
| `export [file]` | Write the server's configuration as a DNS config file, to stdout or to `file` (mode `0600`) |
| `create-token` | Create an API token, or keep a stored one the server still accepts, and save it to a file and/or a Kubernetes Secret |
| `change-password` | Change the password. Succeeds without changes when the new password already works |
| `cluster-state` | Show the cluster's nodes, their state, versions and last sync |
| `version` | Print the version, commit and build date |

Flags go after the command: `technitium-configurator configure --log-level debug dns.yaml`. Every command except `version` first waits up to `DNS_WAIT_TIMEOUT` for the server's `/api/status` to answer, so it can start alongside the server. Logs go to stderr; stdout carries only command output, such as `export`'s YAML.

## Quick start

```bash
docker pull ashtonian/technitium-configurator:3.0.1
```

Images are published for `linux/amd64` and `linux/arm64`. They run as user `65532`, so a host directory the tool writes to must be writable by that user (or pass `--user`).

### 1. Change the default password

Safe to re-run: when the new password already works, it logs that and exits successfully.

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="admin" \
  -e DNS_NEW_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:3.0.1 change-password
```

### 2. Create an API token

A destination is required: `DNS_TOKEN_PATH`, `DNS_K8S_SECRET_NAME`, or both. If one already holds a token, the server is asked whether it still accepts it for this user; a valid token is reused and copied to any destination missing it, and an invalid one is replaced.

Mount a directory, not a single file, for the token file:

```bash
mkdir -p tokens && chmod 777 tokens   # or: --user "$(id -u)"
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  -e DNS_TOKEN_PATH="/app/tokens/token.yaml" \
  -v "$(pwd)/tokens:/app/tokens" \
  ashtonian/technitium-configurator:3.0.1 create-token
```

To store the token in a Kubernetes Secret, run `create-token` where it has Kubernetes credentials: in a pod with a service account (see [`examples/k8s.yaml`](examples/k8s.yaml)), or with a mounted kubeconfig and `KUBECONFIG` set. Set `DNS_K8S_SECRET_NAME`, and optionally `DNS_K8S_SECRET_NAMESPACE` and `DNS_K8S_SECRET_KEY`.

### 3. Apply a DNS config

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_API_TOKEN="your-token" \
  -v "$(pwd)/dns:/app/dns:ro" \
  ashtonian/technitium-configurator:3.0.1 configure /app/dns
```

### 4. Export a running server

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_API_TOKEN="your-token" \
  ashtonian/technitium-configurator:3.0.1 export > dns.yaml
```

Applying an export to the server it came from changes nothing. Applying it to a fresh server reproduces everything the export holds, once you add a password source for each user (passwords cannot be read back) and a `url` for every app the export left without one: apps that are not in the App Store, or every app when the App Store could not be read. An exported `url` is the store's current package, which the header notes when it is newer than the installed version. Cluster membership is not exported, so set the `cluster` section up separately. `export` loads its own output before writing it and refuses to write a file that would not load.

The export contains secrets: TSIG keys, FWD and global proxy credentials, and app configs. It leaves out:

- what the server maintains itself: SOA and apex NS records, DNSSEC records, internal zones;
- the cluster: the `cluster` section, the cluster catalog zone, the cluster's TSIG key, and zones provisioned by secondary catalogs;
- disabled records, user passwords, and certificate passwords the server masks.

Its header summarizes what it found on this server and left out: per zone, how many records were skipped and why (disabled, or a value the configurator cannot write), plus apps without a `url` or with a newer package. The categories in the list above are left out without a note.

## Configuration

The tool takes two kinds of input: **client configuration** (where the server is and how to log in) and **DNS config files** (what the server should look like).

### Client configuration

Each value can come from a default, a client config file (`--config` or `DNS_CLIENT_CONFIG`), an environment variable, or a flag. Later sources win: defaults < file < environment < flags.

| Environment variable | Client config key | Flag | Type | Default | Description |
|---|---|---|---|---|---|
| `DNS_API_URL` | `api_url` | | URL | — (required) | Technitium web service, for example `http://dns-server:5380`. Must not contain credentials, a query or a fragment |
| `DNS_API_TOKEN` | `api_token` | | string | | API token. When set, it is used instead of username and password |
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
| `DNS_K8S_SECRET_NAMESPACE` | `k8s_secret_namespace` | | string | `default` | Namespace of that Secret |
| `DNS_K8S_SECRET_KEY` | `k8s_secret_key` | | string | `api-token` | Key in that Secret |

`configure`, `export` and `cluster-state` need a token or a username and password. `create-token` and `change-password` need a username and password.

A client config file:

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

### DNS config files

[`examples/config.yaml`](examples/config.yaml) is a complete, runnable reference. The top-level keys:

| Key | Type | Description |
|---|---|---|
| `recordPolicy` | `merge` or `replace` | Default [record policy](#record-policies) for the file. Default `merge` |
| `cluster` | object | Cluster init (`mode: primary`) or join (`mode: secondary`); see [Clusters](#clusters) |
| `dnsSettings` | object | Server settings, named as `/api/settings/set` names them |
| `administration` | object | Groups, users and permissions; see [Administration](#administration) |
| `zones` | list | Zones; see [Zones](#zones) |
| `records` | list | Records; see [Records](#records) |
| `apps` | list | DNS Apps; see [DNS Apps](#dns-apps) |

**Several files and documents.** `configure` accepts any number of files and directories, and a file may hold several documents separated by `---`. They are merged into one config: zones, records, apps, groups, users and permissions are combined, while `recordPolicy`, `cluster` and each individual `dnsSettings` key may appear in only one place. A zone, app, group, user or TSIG key declared twice is an error, so nothing is silently overridden.

```bash
technitium-configurator configure base.yaml zones/
```

**Validation.** The whole input is checked before anything changes. YAML syntax errors and keys set in two files stop loading at the first one; after that, every problem is reported at once: unknown keys, missing required fields, values outside the server's ranges, unknown enum values (including ones the server would silently ignore, such as zone ACL options), malformed addresses, endpoints, networks and name server addresses, DS, SSHFP and TLSA digests whose length does not match their digest type, and contradictory combinations. TTLs are limited to 2147483647, the RFC 2181 maximum, although the server stores larger values. App `config` blocks are checked only for being representable as JSON, since their keys belong to each app. Each error names the file and document it came from:

```text
invalid config: zones/b.yaml (document 2): zones[0] (example.com): duplicate zone; first declared at base.yaml: zones[3] (example.com)
```

#### Settings

`dnsSettings` takes any key from `/api/settings/set`. A key you leave out is not sent. An explicit value is always sent, including `false`, `0`, `""` and `[]`; for example `forwarders: []` clears the forwarders.

Some settings depend on others, and the server resolves them in ways a file does not show, so validation enforces them:

- `forwarderProtocol` is required when `forwarders` is non-empty; otherwise the server resets the protocol to `Udp`.
- `enableCachePrefetch: true` with `cachePrefetchTrigger: 0` is rejected; the server would reset the trigger to 9.
- A `proxyType` other than `None` needs `proxyAddress` and `proxyPort`, and replaces the whole proxy, credentials included.
- On a cluster, `dnsServerDomain` must end with the cluster domain.

`tsigKeys` lists your keys. The cluster's own key (named after the cluster catalog) is kept automatically, and keys you remove from the file stay on the server. Each key needs `keyName`, `algorithmName` (`hmac-sha256`, `hmac-sha512` and the other HMAC names the server knows) and a base64 `sharedSecret`; an empty secret would make the server generate a new one on every run.

Changing a web-service setting (`webServiceHttpPort`, `webServiceTlsPort`, `webServiceLocalAddresses`, TLS, HTTP/3, Unix sockets) restarts the web service. The run waits for it to come back; if the change moved it away from `DNS_API_URL`, the run stops and asks you to re-run against the new address.

`enableDnsOverQuic` and `webServiceEnableHttp3` need `libmsquic` on the server. The official Docker image includes it; on other installs the server rejects the change.

#### Zones

| Field | Applies to | Description |
|---|---|---|
| `zone` | all | Zone name; `.` is the root zone. Unicode names are converted to their ASCII form, as the server stores them |
| `type` | all | `Primary`, `Secondary`, `Stub`, `Forwarder`, `SecondaryForwarder`, `Catalog` or `SecondaryCatalog` |
| `catalog` | Primary, Secondary, Stub, Forwarder | Catalog zone to join. `""` means none. On a cluster primary the default is the cluster catalog |
| `useSoaSerialDateScheme` | Primary | SOA serial as a date (set at creation) |
| `primaryNameServerAddresses` | Secondary, Stub, SecondaryForwarder, SecondaryCatalog | Primary servers to transfer from |
| `zoneTransferProtocol`, `tsigKeyName`, `validateZone` | Secondary types | Transfer protocol (`Tcp`, `Tls`, `Quic`), TSIG key and ZONEMD validation |
| `initializeForwarder`, `protocol`, `forwarder`, `dnssecValidation`, `proxyType`, `proxyAddress`, `proxyPort`, `proxyUsername`, `proxyPassword` | Forwarder | The forwarder written at creation |
| `aclSettings` | | `queryAccess`, `queryAccessNetworkACL`, `zoneTransfer`, `zoneTransferNetworkACL`, `zoneTransferTsigKeyNames`, `notify`, `notifyNameServers`, `notifySecondaryCatalogsNameServers`, `update`, `updateNetworkACL`, `updateSecurityPolicies`. Applied every run; an explicit `[]` clears a list |
| `overrideCatalogQueryAccess`, `overrideCatalogZoneTransfer`, `overrideCatalogNotify` | catalog members | Use the zone's own ACLs instead of the catalog's; see [Clusters](#clusters) |
| `recordPolicy` | | Record policy for records in this zone |
| `disabled` | | `true` stops the zone answering, `false` enables it. Applied every run when set |

`updateSecurityPolicies` takes `tsigKeyName|domain|types` triples joined by `|`, with types separated by commas or spaces: `external-dns|*.example.com|A,AAAA,TXT`. Each domain must be inside the zone, and each type a name or number.

#### Records

Every record has `domain` (or its alias `name`) and `type`, plus optionally `zone`, `ttl`, `comments`, `expiryTtl` and `recordPolicy`. A record is placed in the closest zone on the server that contains its name, so `www.example.com` lands in `example.com`, or in `www.example.com` if that zone exists; set `zone` to choose explicitly.

| Type | Fields |
|---|---|
| A, AAAA | `ipAddress` (alias `value`), `ptr`, `createPtrZone`, `updateSvcbHints` |
| NS | `nameServer`, `glue` |
| CNAME, PTR, DNAME, ANAME | `cname`, `ptrName`, `dname`, `aname` |
| MX | `exchange`, `preference` |
| TXT | `text` and `splitText`, or `characterStringsBase64` for byte-exact character strings. `text: ""` is a record without strings. A character string that is itself empty cannot be written by the configurator: it is rejected in a config, and `export` skips such a record and counts it in its header |
| RP | `mailbox`, `txtDomain` |
| SRV | `priority`, `weight`, `port`, `target` |
| NAPTR | `naptrOrder`, `naptrPreference`, `naptrFlags`, `naptrServices`, `naptrRegexp`, `naptrReplacement` |
| DS | `keyTag`, `algorithm`, `digestType`, `digest` |
| SSHFP | `sshfpAlgorithm`, `sshfpFingerprintType`, `sshfpFingerprint` |
| TLSA | `tlsaCertificateUsage`, `tlsaSelector`, `tlsaMatchingType`, `tlsaCertificateAssociationData` |
| SVCB, HTTPS | `svcPriority`, `svcTargetName` (`.` for the owner name), `svcParams` (`key\|value\|key\|value`; leave it out for none), `autoIpv4Hint`, `autoIpv6Hint` |
| URI | `uriPriority`, `uriWeight`, `uri` |
| CAA | `flags`, `tag`, `value` |
| FWD | `protocol`, `forwarder`, `forwarderPriority`, `dnssecValidation`, `proxyType`, `proxyAddress`, `proxyPort`, `proxyUsername`, `proxyPassword`. FWD records always have TTL 0 |
| APP | `appName`, `classPath`, `recordData` |
| Any other type | `rdata` as hex, with `type` set to a type name the server knows (for example `HINFO`) or `TYPE<number>` (for example `TYPE65200`) |

`ptr: true` also needs a reverse zone; add `createPtrZone: true` to create one. It cannot be combined with `ipAddress: request-ip-address`, whose address only the server knows. A record's `zone` must contain its name.

These types cannot be declared:

- SOA, and the DNSSEC records (RRSIG, NSEC, NSEC3, NSEC3PARAM, DNSKEY), which the server maintains;
- ZONEMD, ALIAS, APL and NXNAME;
- types that are not record data: OPT, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY;
- the server's internal CHILD_NS and PARENT_NS.

Values are compared in the form the server stores them, so each of these matches what is on the server:

- names in any case, with or without the trailing dot, and in Unicode or ASCII form;
- IPv6 addresses in any spelling, with or without brackets;
- TXT text by its character strings, however it was split; `text: ""` is a TXT record without strings;
- RP mailboxes as `user.domain` or `user@domain`;
- DS, SSHFP and TLSA values by name or number;
- SVCB parameters by their typed values;
- FWD records by every field, defaults included;
- URIs as the server normalizes them: scheme and host case, default port, `.` and `..` segments, and escaped letters, digits and `-._~`. Other escapes, such as `%2F`, stay distinct from the characters they encode.

A URI the server normalizes in some way not listed here is re-sent on each run, where the server ignores the duplicate.

#### Administration

```yaml
administration:
  groups:
    - name: "dns-readers"
      description: "Read-only DNS access"
  users:
    - username: "monitoring"
      displayName: "Monitoring"
      passwordEnv: "MONITORING_PASSWORD"   # or password / passwordFile
      groups: ["dns-readers"]
  permissions:
    - section: "Zones"
      groups:
        dns-readers: [view]
```

- Groups and users are created if absent. A user needs `password`, `passwordFile` or `passwordEnv` only when the run has to create it, and the source is read only then, so it may be gone on later runs. The password is never compared or changed afterwards.
- `displayName`, `disabled`, `sessionTimeoutSeconds` and `description` are applied when set.
- `groups` on a user adds memberships; existing memberships the file does not name are kept.
- `permissions` sets the listed grants for a section (`Dashboard`, `Zones`, `Cache`, `Allowed`, `Blocked`, `Apps`, `DnsClient`, `Settings`, `DhcpServer`, `Administration`, `Logs`) and keeps every other grant, including the built-in Administrators. Access values are `view`, `modify` and `delete`. Every user and group named must exist on the server or be declared in the file; the server silently drops grants for unknown names, so the run fails instead, and it checks that the server kept every grant it sent.
- Per-zone permissions, SSO and LDAP are not managed.

## Clusters

Add a `cluster` section and `configure` applies it after the settings and before everything else. Only the primary needs settings, zones and records; secondaries need only the `cluster` section.

```yaml
# primary.yaml
cluster:
  mode: "primary"
  domain: "dns-cluster.example.com"
  nodeIPs: "10.0.0.1"                  # comma-separated; applied every run
  configRefreshIntervalSeconds: 60     # primary timing options, applied every run
  configRetryIntervalSeconds: 30
  heartbeatRefreshIntervalSeconds: 15
  heartbeatRetryIntervalSeconds: 10
dnsSettings:
  dnsServerDomain: "primary.dns-cluster.example.com"   # must end with the cluster domain
```

```yaml
# secondary.yaml
cluster:
  mode: "secondary"
  nodeIPs: "10.0.0.2"
  primaryURL: "http://primary-dns:5380"   # a host name; HTTPS uses port 53443
  primaryIP: "10.0.0.1"                   # when the secondary cannot resolve that name
  primaryUsername: "admin"
  primaryPassword: "primary-password"
  primaryTotp: ""                         # one-time code for a 2FA primary user; join only
  ignoreCertErrors: false
```

- **Order.** Configure the primary first, then each secondary.
- **Credentials on secondaries.** Joining replaces a secondary's users with the primary's, and the secondary drops API tokens of its own when it syncs. The run continues as the primary's user, and later runs that fail with the secondary's own token or credentials retry with the primary's credentials from the `cluster` section, so give secondaries a username and password rather than a token. `primaryTotp` works for the join only, because a one-time code expires; for later runs, use a primary user without two-factor authentication, for example one created for automation under `administration` on the primary.
- **Topology.** The run checks that the node's role and cluster domain match the file and fails if they do not. Leaving, removing and promoting nodes are not managed.
- **Server name.** Cluster init renames the server into the cluster domain, so a `dnsServerDomain` in the file must already end with it.

**Zone replication.** Zones replicate through the cluster catalog zone, `cluster-catalog.<cluster domain>`. On the primary, every Primary, Secondary, Stub and Forwarder zone joins it unless the zone sets `catalog` itself (`catalog: ""` keeps a zone on the primary only). A zone already in another catalog is not moved. If the account cannot read the cluster state (it needs Administration view permission), the run fails rather than guess, unless every zone sets `catalog`.

**Catalog ACLs.** A catalog member follows the catalog's query access, zone transfer and notify settings unless the zone sets the matching override to `true`. Overrides are never turned on for you. When a member zone declares one of those groups without setting its override, the run warns that the declared values are not in effect; set the override to `true` to apply them, or `false` to keep the catalog's and silence the warning.

The cluster catalog allows zone transfers only from the cluster nodes, signed with the cluster's TSIG key (`cluster-catalog.<cluster domain>`), and notifies the nodes directly; that is what replicates member zones. A zone that overrides zone transfer or notify replaces it, so it must allow the node IPs and list the cluster key in `zoneTransferTsigKeyNames`, or it stops replicating. Leaving zone transfer inherited is usually right; query access can be overridden safely.

## DNS Apps

Any app from the Technitium App Store, or any app package URL, can be installed.

```yaml
apps:
  - name: "Advanced Blocking"
    url: "https://download.technitium.com/dns/apps/AdvancedBlockingApp-v11.2.1.zip"
    config: { ... }          # the app's complete config document
  - name: "NO DATA"
    url: "https://download.technitium.com/dns/apps/NoDataApp-v6.zip"
```

- `config` is converted to JSON and passed to the app, so every field the app accepts can be used. YAML merge keys (`<<`) are resolved; duplicate keys (including a second `<<` in one mapping: merge several with `<<: [*a, *b]`) and aliases that contain themselves are errors. Give the **complete** document: apps reject a config with missing keys. Start from the app's `dnsApp.config` in the [Technitium source](https://github.com/TechnitiumSoftware/DnsServer/tree/master/Apps).
- Leave `config` out to keep the app's current config. Apps used only through APP records (NO DATA, Auto PTR, Wild IP and others) need none.
- Config is written only when it differs from the stored config, compared as JSON; comments in the stored config are ignored, as the apps ignore them. Numbers keep every digit in any YAML spelling, so 64-bit integers and long decimals are passed exactly.
- `url` is needed only to install the app. An installed app is not downloaded again; app upgrades and uninstalls are not performed.
- Package URLs and the server versions they need are in the App Store catalogue, [`Apps/apps2.json`](https://github.com/TechnitiumSoftware/DnsServer/blob/master/Apps/apps2.json). For v15.6: Advanced Blocking `AdvancedBlockingApp-v11.2.1.zip`, Advanced Forwarding `AdvancedForwardingApp-v5.2.zip`.
- Apps that answer through APP records (Split Horizon, Geo, Failover, Weighted Round Robin and others) are configured with `type: APP` records. Apps are installed before APP records and every other record type except FWD.

## Deployment

### Docker Compose

[`examples/docker-compose.yaml`](examples/docker-compose.yaml) starts a server and runs the configurator in order: change the password, then apply the config. A commented section shows a two-node cluster.

### Kubernetes

[`examples/k8s.yaml`](examples/k8s.yaml) runs the configurator as a Job against an existing Technitium server. It assumes the [External Secrets Operator](https://external-secrets.io/) for credentials. Its init containers change the password, then create the API token; the main container applies the config. Every step is safe to re-run.

The Role lets the Job read and update one Secret by name. Kubernetes cannot limit `create` to a name, so a second rule allows creating Secrets in the namespace; pre-create the Secret and drop that rule to avoid it. If the DNS config contains secrets (TSIG keys, user passwords, app credentials), mount it from a Secret rather than a ConfigMap.

### Image

The image is built `FROM scratch` with a CA bundle and the static binary at `/technitium-configurator`. It runs as user `65532`, and its working directory is `/app`, so a relative `config.yaml` resolves to `/app/config.yaml`.

## External dependencies

| Dependency | Used for | Notes |
|---|---|---|
| Technitium DNS Server v15.6+ | Everything, through its HTTP API | Reachable at `DNS_API_URL` |
| Technitium App Store (`download.technitium.com`) | App packages and the store catalogue, fetched **by the DNS server** | When an app must be installed, and during `export`, which looks up each app's package URL |
| Kubernetes API | `create-token` storing the token in a Secret | Only when `DNS_K8S_SECRET_NAME` is set |
| Docker | The e2e test suite | Development only |

## Interfaces

- **CLI** — the commands, flags, environment variables and exit codes above.
- **DNS config schema** — the YAML described above, versioned with the major version (v3).
- **Go module** — `github.com/ashtonian/technitium-configurator/v3`. `pkg/technitium` is a typed client for the Technitium API and the config model; it follows the CLI's major version but is not otherwise a stable library API.

## Building, running and testing

```bash
go build -o technitium-configurator .
./technitium-configurator version

docker build -t technitium-configurator .
docker buildx build --platform linux/amd64,linux/arm64 -t technitium-configurator .

go test -race ./...                  # unit tests
go test -tags e2e ./e2e              # needs Docker; starts Technitium 15.6.1 containers
```

The e2e suite checks the values a fresh install ends up with; that an unchanged re-run writes nothing but settings and zone options; record policies and values the server stores in another form; PTR preservation; IDN names; ACL clearing; administration; export applied back to its server and restored onto a fresh one; the binary's exit codes and output streams; and a two-node cluster in which zones replicate, a local zone stays local, and the secondary re-runs with its original credentials and with a token it no longer has.

GitHub Actions runs vet, lint, the unit tests, govulncheck and the e2e suite on every pull request and push. Only when they pass does it build both platforms' binaries, check each one's architecture and that it reports the version (for a release, the tag without its `v`), and then build and push the images from the same inputs. Pushes to `main` publish `beta` and `beta-<date>-<sha>`. A `v*` tag publishes `<version>` (and `v<version>` for versions without a prerelease suffix), moves `latest` only for those, marks tags with a suffix as prereleases, and creates a GitHub release from that version's section of `RELEASE_NOTES.md`.

## Operations

**Health.** The tool is a run-to-completion command. Its exit code is the health signal: `0` on success, `1` when anything failed. In Kubernetes, a failed Job is the alert.

**Logs.** Text lines on stderr. A `configure` run that reaches its resources ends with `Configuration complete created=… applied=… unchanged=… conflicts=… failed=…`; a run that stops earlier (invalid config, records that cannot be placed, a settings or cluster failure) ends with `level=ERROR msg="Command failed"`. Failures are `level=ERROR msg=Failed item=…`, conflicts are `level=WARN`, and values that `merge` left in place are reported at `info`. At `debug`, every API call is logged with its method, path, non-secret query parameters, status and duration.

### Troubleshooting

| Symptom | Check | Fix |
|---|---|---|
| `invalid config: …` | The listed lines; every validation problem is reported at once | Correct the file. Nothing was changed |
| `records cannot be applied; nothing was changed: …` | Each listed record: no zone contains it, or its name and type conflict | Declare the zone or set `zone`, and fix the conflict |
| `check API token: …` | Does the token still exist? A joined secondary drops its own tokens | Use a username and password, or keep the primary's credentials in the `cluster` section |
| `… also needs a one-time password` | The primary's user has two-factor authentication | Use a primary user without two-factor authentication for runs after the join |
| `no such group … on the server` in `permissions` | Is the name spelled as on the server, or declared under `administration`? | Fix the name or declare the group or user |
| `the app is not installed and has no url` | The app is missing on this server | Add its package `url` |
| `server not ready after 60s` | Is the server up, and is `DNS_API_URL` reachable from where the tool runs? | Fix the URL or network, or raise `DNS_WAIT_TIMEOUT` |
| `login as "admin": … Invalid username or password` | Did `change-password` already run? On a joined secondary, the users are the primary's | Use the current password. For secondaries, keep the primary's credentials in the `cluster` section |
| `Max limit of 5 attempts exceeded` | The server blocked the client's address after failed logins | Fix the credentials and wait for the block to expire |
| `N operation(s) failed: …` | The `level=ERROR` lines name each item and the server's message | Fix the item and re-run; what succeeded is not redone |
| `No reverse zone available to add PTR record` | `ptr: true` without a reverse zone | Add `createPtrZone: true`, or declare the reverse zone |
| `The given key was not present in the dictionary` on an app | The app config is incomplete | Give the app's complete config document |
| `read cluster state to choose zone catalogs` | The token's user lacks Administration view permission | Grant it, or set `catalog` on each zone |
| A zone does not reach the secondaries | `/api/zones/options/get` on the primary: is `catalog` the cluster catalog? Does the zone override zone transfer? | Remove `catalog: ""`, or leave zone transfer inherited, or admit the cluster nodes and key in the zone's ACL |
| `dnsServerDomain … must end with the cluster domain` | The server's cluster domain | Rename it within the cluster domain |
| `web service did not come back after the settings change` | Did the run change the web port, addresses or TLS? | Re-run against the new address |
| `the server redirected to …` | HTTP-to-HTTPS redirect is on | Use the HTTPS URL |
| `WARN … exists with a different value` | A CNAME, DNAME, APP or PTR differs from the file | Leave it, or set `recordPolicy: replace` |
| `WARN … is not in effect; the catalog's applies` | The zone joins a catalog without an override | Set the named override to `true` or `false` |
| The Kubernetes Job keeps restarting | The init container logs (`change-password`, `create-token`) | Check the credentials in the Secret and the RBAC rules |

## Security

- **Credentials in transit.** The API token goes in an `Authorization: Bearer` header and passwords in POST bodies, never in URLs. Redirects are not followed. Use an `https://` URL when the server is not on a trusted network.
- **Credentials in logs.** Request and response bodies are never logged, connection errors name the API path instead of the URL, and a URL containing credentials is rejected. Conflict and stale-value messages leave out APP record data and proxy passwords.
- **Token storage.** The token file gets mode `0600` before the token is written. It is replaced atomically when its directory is writable; a file bind-mounted on its own or in a read-only directory is overwritten in place, and only if it can be made private. The Kubernetes Role is limited to one Secret, plus `create`, which cannot be limited by name.
- **Secrets in config.** TSIG secrets, proxy and app credentials and initial user passwords may appear in DNS config files and in `export` output; store them as secrets. Prefer `passwordEnv` or `passwordFile` to `password`.
- **Clusters.** `ignoreCertErrors` applies only to the join call; use it only on networks you trust.
- **Image.** `FROM scratch`, a pinned builder image, no shell, non-root user `65532`.

## Limitations

- Nothing is pruned: zones, records, apps, groups, users and TSIG keys removed from the file stay on the server. Only `recordPolicy: replace` removes values, and only for the names and types the file declares.
- A zone that exists with a different type is reported, not converted.
- Apps are not upgraded or uninstalled.
- Cluster topology is set once; leaving, removing and promoting nodes are not managed.
- Settings are not transactional: the server applies them in order and keeps earlier ones when a later one fails. Validation catches the values it can know are wrong; one the server rejects for its own reasons, such as QUIC without `libmsquic`, can still leave earlier settings applied.
- Not managed: per-zone permissions, DNSSEC signing, allowed and blocked domain lists, DHCP, SSO, LDAP.

## Code map

| Path | Contents |
|---|---|
| `main.go` | CLI entry: client configuration precedence, logging, signal handling, exit codes, `version` output |
| `cmd/cli.go` | Command-line parsing: commands, flags, arguments, usage text |
| `cmd/commands.go` | Commands: `configure` entry, `create-token`, `change-password`, `export`, `cluster-state`; authentication |
| `cmd/configure.go` | One configure pass: checks before any change, then settings, cluster, administration, zones, FWD records, apps, other records |
| `pkg/technitium/client.go`, `errors.go`, `logging.go` | HTTP client, response envelope, typed errors, request logging |
| `pkg/technitium/config.go`, `validate.go` | DNS config schema, multi-file loading and merging, validation |
| `pkg/technitium/plan.go` | Decisions without I/O: catalogs, ACL overrides, record placement and plans, TSIG merging |
| `pkg/technitium/rdata.go`, `names.go`, `rrtypes.go` | Record value comparison and conversion; canonical DNS names and zone keys; the server's record type table |
| `pkg/technitium/dns_settings.go`, `zone.go`, `records.go`, `apps.go`, `cluster.go`, `admin.go` | API calls and types per area |
| `pkg/technitium/export.go` | `export`: reading a server back into the schema |
| `pkg/technitium/client_config.go` | Client configuration and its validation |
| `pkg/kube` | Kubernetes Secret storage for `create-token` |
| `e2e/` | End-to-end tests against Technitium containers, and the built binary's exit codes |
| `examples/` | DNS config, Docker Compose and Kubernetes examples |
| `.github/workflows/` | CI: test, e2e, image build and release (`docker.yml`); Docker Hub overview publishing (`dockerhub-description.yml`) |
| `.github/DOCKERHUB.md` | The Docker Hub overview; changes are published when they reach `main` |
