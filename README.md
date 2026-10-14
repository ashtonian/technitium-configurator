# Technitium Configurator

[![Build](https://github.com/ashtonian/technitium-configurator/actions/workflows/docker.yml/badge.svg)](https://github.com/ashtonian/technitium-configurator/actions/workflows/docker.yml)
[![Docker Image](https://img.shields.io/docker/v/ashtonian/technitium-configurator?sort=semver&label=docker)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Docker Pulls](https://img.shields.io/docker/pulls/ashtonian/technitium-configurator)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Docker Image Size](https://img.shields.io/docker/image-size/ashtonian/technitium-configurator/latest)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ashtonian/technitium-configurator)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Technitium Configurator sets up a [Technitium DNS Server](https://technitium.com/dns/) from YAML files. Describe zones, records, settings, apps, users and clusters in a file and run `configure`. Each run creates what is missing, applies the settings you list and leaves everything else alone, so you can run it as often as you like.

```yaml
# dns.yaml
dnsSettings:
  forwarders: ["1.1.1.1", "9.9.9.9"]
  forwarderProtocol: "Udp"

zones:
  - zone: "home.arpa"
    type: "Primary"

records:
  - domain: "nas.home.arpa"
    type: "A"
    ipAddress: "192.168.1.10"
    ptr: true              # also add the reverse record 10.1.168.192.in-addr.arpa
    createPtrZone: true    # and create its reverse zone if it is missing
  - domain: "files.home.arpa"
    type: "CNAME"
    cname: "nas.home.arpa"
```

```console
$ technitium-configurator configure dns.yaml
level=INFO msg="DNS settings applied"
level=INFO msg="Created zone" zone=home.arpa type=Primary
level=INFO msg="Created record" domain=nas.home.arpa type=A
level=INFO msg="Created record" domain=files.home.arpa type=CNAME
level=INFO msg="Configuration complete" created=3 applied=2 unchanged=0 conflicts=0 failed=0

$ technitium-configurator configure dns.yaml      # again: nothing left to create
level=INFO msg="DNS settings applied"
level=INFO msg="Configuration complete" created=0 applied=2 unchanged=3 conflicts=0 failed=0

$ dig @dns-server +short files.home.arpa
nas.home.arpa.
192.168.1.10
```

Log lines in this README have their timestamps trimmed. `applied` counts the settings and zone options, which are sent on every run; sending the same values again changes nothing.

The tool also changes the admin password, creates API tokens, initializes and joins clusters, and exports a running server's configuration as a file you can edit and apply again.

**Contents:** [Try it locally](#try-it-locally) · [Use it with your server](#use-it-with-your-server) · [Recipes](#recipes) · [How a run works](#how-a-run-works) · [Running it](#running-it) · [API tokens](#api-tokens) · [Reference](#reference) · [Operations](#operations) · [Security](#security) · [Limitations](#limitations)

## Overview

DNS is critical, so its configuration should be repeatable. Technitium stores its configuration in binary files, and there is no declarative way to manage it; this tool fills that gap through Technitium's HTTP API.

- **Bootstrap, then re-run safely.** Zones, records, apps, groups and users are created when absent. Settings, zone options and the primary's cluster timing options are sent on every run; app config is written when it differs. Nothing is pruned: what the file leaves out stays on the server.
- **Every v15.6 server setting.** All 131 keys `/api/settings/set` accepts. Explicit `false`, `0`, `""` and `[]` are applied.
- **Zones and records.** All zone types, including the root zone, with ACLs, update policies and catalog membership. Every record type the API has fields for, and other types as hex RDATA, with a [record policy](#record-policies) that chooses between adding values and replacing them.
- **Any DNS App.** Install from a package URL and pass its config through as JSON.
- **Clusters.** Initialize a primary or join a secondary; zones on the primary replicate through the cluster catalog.
- **Users, groups and permissions**, created if absent and merged into the existing grants.
- **Export.** Write a server's configuration as a config file you can edit and apply again.
- **Checked before anything changes.** Unknown keys and invalid values fail the run before the first change. Problems only the server can find fail that item, and every failure makes the run exit non-zero.
- **Quiet re-runs.** Records, apps, users, groups and permissions are compared with the server in the form it stores them, and nothing that matches is sent again.

Requires **Technitium DNS Server v15.6.0 or later**; see [Compatibility](#compatibility).

## Try it locally

Needs Docker. This starts a Technitium 15.6.1 server, changes its admin password and applies [`examples/config.yaml`](examples/config.yaml): two zones, records with a reverse zone, a TSIG key, and the Advanced Blocking and Advanced Forwarding apps.

```bash
git clone https://github.com/ashtonian/technitium-configurator.git
cd technitium-configurator/examples
docker compose up -d
docker compose wait configurator-configure
docker compose logs --no-log-prefix configurator-password configurator-configure
```

```console
level=INFO msg="Password changed" user=admin
level=INFO msg="DNS settings applied"
level=INFO msg="Created zone" zone=example.com type=Primary
level=INFO msg="Created zone" zone=corp.internal type=Forwarder
level=INFO msg="Installed app" app="Advanced Blocking"
level=INFO msg="App config applied" app="Advanced Blocking"
level=INFO msg="Installed app" app="Advanced Forwarding"
level=INFO msg="App config applied" app="Advanced Forwarding"
level=INFO msg="Installed app" app="NO DATA"
level=INFO msg="Created record" domain=www.example.com type=A
level=INFO msg="Created record" domain=mail.example.com type=MX
level=INFO msg="Created record" domain=example.com type=TXT
level=INFO msg="Created record" domain=docs.example.com type=CNAME
level=INFO msg="Replaced records" item="record pool.example.com A" values=2
level=INFO msg="Configuration complete" created=9 applied=6 unchanged=0 conflicts=0 failed=0
```

The server answers on `127.0.0.1:1053`, and the web console is at <http://localhost:5380> (user `admin`, password `securepassword`):

```console
$ dig @127.0.0.1 -p 1053 +short pool.example.com
192.168.1.21
192.168.1.22
```

Edit `config.yaml` and apply it again; only what changed is written:

```bash
docker compose run --rm --no-deps configurator-configure
```

`docker compose down -v` removes the server and its data. [`examples/cluster`](examples/cluster) does the same for a two-node cluster.

## Use it with your server

You need the server's web service URL (port `5380` by default) reachable from where the tool runs, and the admin password. Every step is safe to repeat. These examples use the Docker image; the [binary](#without-docker) takes the same environment variables and arguments.

### 1. Change the default password

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="admin" \
  -e DNS_NEW_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:3.1.0 change-password
```

```console
level=INFO msg="Password changed" user=admin
```

A re-run logs `Password is already set to the new value` and exits `0`. It tries the new password first, so re-runs do not count as failed logins.

### 2. Write a config

Start from the example at the top of this page, a [recipe](#recipes), or [an export of a server you already run](#start-from-a-server-you-already-run). Put it in a directory, here `dns/config.yaml`.

### 3. Apply it

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  -v "$(pwd)/dns:/app/dns:ro" \
  ashtonian/technitium-configurator:3.1.0 configure /app/dns
```

`configure` takes files and directories; a directory means its `*.yaml` and `*.yml` files. The whole input is checked before anything changes, so a mistake stops the run with the server untouched:

```console
level=ERROR msg="Command failed" error="parse /app/dns/config.yaml: line 7: unknown record field \"ipAdress\"" command=configure
level=ERROR msg="Command failed" error="invalid config: /app/dns/config.yaml: records[1] (tv.home.arpa A).ipAddress \"192.168.1.300\" is not an IP address" command=configure
level=ERROR msg="Command failed" error="records cannot be applied; nothing was changed: /app/dns/config.yaml: records[2] (www.example.org A): no zone contains this name; declare the zone or set zone on the record" command=configure
```

Re-run it after every change to the file, from a shell, CI, a [Compose service](#docker-compose) or a [Kubernetes Job](#kubernetes).

### Start from a server you already run

`export` writes a server's configuration as a config file. Applying it back to the same server changes nothing, so it is a safe starting point to put under version control:

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:3.1.0 export > dns/config.yaml
```

```yaml
# Exported by technitium-configurator from http://dns-server:5380.
# It contains secrets (TSIG keys, proxy and app credentials): keep it private.
# - Users are exported without passwords. Add password, passwordFile or passwordEnv to any user the file must be able to create.
dnsSettings:
  dnsServerDomain: dns.home.arpa
  dnsServerLocalEndPoints:
    - 0.0.0.0:53
    - '[::]:53'
  defaultRecordTtl: 3600
  # (trimmed: an export lists every server setting)
zones:
  - zone: home.arpa
    type: Primary
    aclSettings:
      queryAccess: Allow
      zoneTransfer: AllowOnlyZoneNameServers
      notify: ZoneNameServers
      update: Deny
records:
  - domain: files.home.arpa
    type: CNAME
    zone: home.arpa
    ttl: 3600
    cname: nas.home.arpa
  - domain: nas.home.arpa
    type: A
    zone: home.arpa
    ttl: 3600
    ipAddress: 192.168.1.10
```

An export lists all of the roughly 130 server settings. Delete the ones you do not want to manage: a setting left out of the file is not sent. See [Export](#export) for what an export leaves out and what it needs before it can rebuild a fresh server.

## Recipes

Each recipe is a complete config file. Combine them by passing several files, or a directory, to `configure` ([Several files](#several-files-and-documents)).

### Forward queries upstream over DNS-over-TLS

```yaml
dnsSettings:
  forwarders: ["cloudflare-dns.com (1.1.1.1)", "cloudflare-dns.com (1.0.0.1)"]
  forwarderProtocol: "Tls"
```

`forwarderProtocol` is required whenever `forwarders` is non-empty. `forwarders: []` clears them, and the server resolves recursively.

### Send one domain to another DNS server

A Forwarder zone answers its names by asking another server, for example an office or Active Directory DNS server:

```yaml
zones:
  - zone: "corp.example.com"
    type: "Forwarder"
    initializeForwarder: true
    protocol: "Udp"
    forwarder: "10.20.0.53"
```

### Let external-dns manage a zone (RFC 2136)

A zone that [external-dns](https://github.com/kubernetes-sigs/external-dns) can update and read back with a TSIG key:

```yaml
dnsSettings:
  tsigKeys:
    - keyName: "external-dns"
      algorithmName: "hmac-sha256"
      sharedSecret: "c2VjcmV0LWZvci1leHRlcm5hbC1kbnMtZXhhbXBsZQ=="   # generate with: openssl rand -base64 32

zones:
  - zone: "k8s.home.arpa"
    type: "Primary"
    aclSettings:
      # external-dns lists records with a zone transfer and writes them with dynamic updates.
      zoneTransfer: "UseSpecifiedNetworkACL"
      zoneTransferNetworkACL: ["10.0.0.0/8"]           # where external-dns runs
      zoneTransferTsigKeyNames: ["external-dns"]
      update: "UseSpecifiedNetworkACL"
      updateNetworkACL: ["10.0.0.0/8"]
      updateSecurityPolicies: "external-dns|k8s.home.arpa|ANY|external-dns|*.k8s.home.arpa|ANY"
```

The matching external-dns flags:

```text
--provider=rfc2136
--rfc2136-host=<DNS server address>
--rfc2136-port=53
--rfc2136-zone=k8s.home.arpa
--rfc2136-tsig-axfr
--rfc2136-tsig-keyname=external-dns
--rfc2136-tsig-secret-alg=hmac-sha256
--rfc2136-tsig-secret=<the sharedSecret>
```

Updates and transfers without the key are refused. Records that external-dns writes are not in the file, and the default `merge` [record policy](#record-policies) leaves them alone.

### Block ads and trackers

The [Advanced Blocking](https://github.com/TechnitiumSoftware/DnsServer/tree/master/Apps/AdvancedBlockingApp) app with two blocklists for every client. An app needs its complete config document, so every key is present:

```yaml
dnsSettings:
  enableBlocking: false     # the app blocks; the built-in blocking is off

apps:
  - name: "Advanced Blocking"
    url: "https://download.technitium.com/dns/apps/AdvancedBlockingApp-v11.2.1.zip"
    config:
      enableBlocking: true
      blockingAnswerTtl: 30
      blockListUrlUpdateIntervalHours: 24
      networkGroupMap:
        "0.0.0.0/0": "home"
        "::/0": "home"
      groups:
        - name: "home"
          enableBlocking: true
          allowTxtBlockingReport: true
          blockAsNxDomain: true
          blockingAddresses: ["0.0.0.0", "::"]
          allowed: []
          blocked: []
          allowListUrls: []
          blockListUrls:
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt"
            - "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt"
          allowedRegex: []
          blockedRegex: []
          regexAllowListUrls: []
          regexBlockListUrls: []
          adblockListUrls: []
```

[`examples/config.yaml`](examples/config.yaml) also configures Advanced Forwarding. See [DNS Apps](#dns-apps) for finding an app's package URL and config.

### Records of each common type

```yaml
zones:
  - zone: "home.arpa"
    type: "Primary"

records:
  - { domain: "nas.home.arpa",        type: "A",     ipAddress: "192.168.1.10" }
  - { domain: "nas.home.arpa",        type: "AAAA",  ipAddress: "fd00::10" }
  - { domain: "files.home.arpa",      type: "CNAME", cname: "nas.home.arpa" }
  - { domain: "home.arpa",            type: "MX",    exchange: "mail.home.arpa", preference: 10 }
  - { domain: "home.arpa",            type: "TXT",   text: "v=spf1 -all" }
  - { domain: "home.arpa",            type: "CAA",   flags: 0, tag: "issue", value: "letsencrypt.org" }
  - { domain: "_ldap._tcp.home.arpa", type: "SRV",   priority: 0, weight: 5, port: 389, target: "nas.home.arpa" }
  - { domain: "lab.home.arpa",        type: "NS",    nameServer: "ns1.lab.home.arpa", glue: "192.168.2.53" }
  - { domain: "home.arpa",            type: "HTTPS", svcPriority: 1, svcTargetName: ".", svcParams: "alpn|h2,h3" }
  - { domain: "printer.home.arpa",    type: "A",     ipAddress: "192.168.1.20", ttl: 300, comments: "office printer" }
```

A record goes into the closest zone that contains its name. Without `ttl`, the server's `defaultRecordTtl` applies. Every type and field is in [Records](#records).

### A read-only user for monitoring

```yaml
administration:
  groups:
    - name: "dns-readers"
      description: "Read-only DNS access"
  users:
    - username: "monitoring"
      displayName: "Monitoring"
      passwordEnv: "MONITORING_PASSWORD"   # read only when the user is created
      groups: ["dns-readers"]
  permissions:
    - section: "Dashboard"
      groups:
        dns-readers: [view]
    - section: "Zones"
      groups:
        dns-readers: [view]
```

```console
level=INFO msg="Created group" group=dns-readers
level=INFO msg="Created user" user=monitoring
level=INFO msg="Updated user" user=monitoring
level=INFO msg="Permissions applied" section=Dashboard
level=INFO msg="Permissions applied" section=Zones
```

See [Administration](#administration).

### Split the config across files

```text
dns/
├── 00-settings.yaml        dnsSettings
├── 10-home.arpa.yaml       zones and records for home.arpa
└── 20-lab.home.arpa.yaml   zones and records for lab.home.arpa
```

`configure dns/` reads the files in name order and merges them. Lists combine; a single value, such as one setting, may be set in only one file, and declaring the same zone twice is an error:

```console
level=ERROR msg="Command failed" error="invalid config: dns/20-lab.home.arpa.yaml (document 2): zones[0] (home.arpa): duplicate zone; first declared at dns/10-home.arpa.yaml: zones[0] (home.arpa)" command=configure
```

### A two-node cluster

[`examples/cluster`](examples/cluster) runs this with Docker Compose. The primary file holds the whole DNS config; the secondary only joins:

```yaml
# primary.yaml
cluster:
  mode: "primary"
  domain: "dns-cluster.example.com"
  nodeIPs: "172.28.0.10"
  configRefreshIntervalSeconds: 60

dnsSettings:
  dnsServerDomain: "primary.dns-cluster.example.com"   # must end with the cluster domain

zones:
  - zone: "example.com"            # joins the cluster catalog, so it replicates
    type: "Primary"
  - zone: "lab.example.com"
    type: "Primary"
    catalog: ""                    # stays on the primary only

records:
  - domain: "www.example.com"
    type: "A"
    ipAddress: "10.0.0.1"
```

```yaml
# secondary.yaml
cluster:
  mode: "secondary"
  nodeIPs: "172.28.0.11"
  primaryURL: "http://dns-primary:5380"
  primaryIP: "172.28.0.10"
  primaryUsername: "admin"
  primaryPassword: "securepassword"
```

```console
# primary
level=INFO msg="DNS settings applied"
level=INFO msg="Cluster initialized" domain=dns-cluster.example.com
level=INFO msg="Re-authenticated after cluster operation" user=admin
level=INFO msg="Cluster options applied" options.configRefreshIntervalSeconds=60
level=INFO msg="Created zone" zone=example.com type=Primary
level=INFO msg="Created zone" zone=lab.example.com type=Primary
level=INFO msg="Created record" domain=www.example.com type=A
level=INFO msg="Configuration complete" created=4 applied=4 unchanged=0 conflicts=0 failed=0
# secondary
level=INFO msg="Joined cluster" primaryURL=http://dns-primary:5380
level=INFO msg="Re-authenticated after cluster operation" user=admin
level=INFO msg="Configuration complete" created=1 applied=0 unchanged=0 conflicts=0 failed=0
```

Configure the primary first, then each secondary. See [Clusters](#clusters) for credentials, replication and catalog ACLs.

## How a run works

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

### Record policies

`recordPolicy` decides what happens when a name and type already have values on the server. Set it for the whole file, override it per zone, and override that per record.

Say the file declares `nas.home.arpa A 192.168.1.10`, and someone added `192.168.1.99` for the same name in the web console. With `merge`, the default, the run leaves the extra value and says so:

```console
level=INFO msg="Record values on the server that the config does not list; left in place (recordPolicy: replace removes them)" item="record nas.home.arpa A" values=[192.168.1.99]
```

With `recordPolicy: "replace"` on that record, the file owns the name and type, and the server ends up with only `192.168.1.10`:

```console
level=INFO msg="Replaced records" item="record nas.home.arpa A" values=1
```

| Policy | Use it for |
|---|---|
| `merge` (default) | Zones you share with other writers, such as external-dns, DHCP or the web console |
| `replace` | Names the file owns completely |

Under `merge`, a CNAME, DNAME or APP record that exists with a different value is reported as a conflict and left alone, because a name can hold only one of them. A PTR created by an earlier run or by hand is never overwritten under `merge`. The TTL, comments and expiry of a value that already exists are not changed.

Under `replace`, the declared values are compared with the server first, and nothing is written when they already match, including the TTL, comments, expiry TTL and NS glue the file sets. When they differ, the set is rewritten, `ptr: true` included. A name with several values briefly has fewer while the run writes them.

### Validation

Checks happen in three stages:

1. **Loading the files.** A YAML syntax error, an unknown key or a key set in two files stops loading at once. After that, every problem that can be judged from the files alone is reported together: missing required fields, values outside the server's ranges, unknown enum values (including ones the server would silently ignore, such as zone ACL options), malformed addresses, endpoints, networks and name server addresses, DS, SSHFP and TLSA digests whose length does not match their digest type, and contradictory combinations. TTLs are limited to 2147483647, the RFC 2181 maximum, although the server stores larger values. App `config` blocks are checked only for being representable as JSON, since their keys belong to each app. Each error names the file and document it came from.
2. **Before any change.** The run reads the server's zones and places every record. A record no zone contains, a record naming a zone that does not exist, two values for a CNAME, DNAME or APP name, records of one name and type with different policies, an FWD record outside a Forwarder zone, and cluster timing options the server would reject all stop the run with nothing changed.
3. **During the run.** Some problems only the server can find, such as an app config the app rejects, a missing reverse zone for `ptr: true`, or QUIC without `libmsquic`. These fail that item, or stop the run when they happen in settings or the cluster.

[Step 3 above](#3-apply-it) shows an error from each of the first two stages.

### Order

Settings, cluster, administration, zones (catalog zones first), FWD records, apps, then the other records. FWD records come before apps because they decide how the server resolves the App Store's address; the other records come last so that a record can refer to an app or zone declared in the same file.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, or help was asked for (`help`, `--help`, `<command> --help`). Conflicts are logged as warnings and do not change the code |
| `1` | The config is invalid, a prerequisite (settings, cluster, login) failed, or at least one operation failed. The run continues past individual failures and lists every one at the end |
| `2` | Bad command-line usage: no command, an unknown command, an unknown flag, or too many arguments (`version` and `help` take none). The error and the usage text go to stderr |

## Running it

### Docker

```bash
docker pull ashtonian/technitium-configurator:3.1.0
```

Images are published for `linux/amd64` and `linux/arm64`. The image is built `FROM scratch` with a CA bundle and the static binary at `/technitium-configurator`. It runs as user `65532`, so a host directory the tool writes to must be writable by that user, or pass `--user "$(id -u):$(id -g)"`. Its working directory is `/app`, so a relative `config.yaml` resolves to `/app/config.yaml`.

### Docker Compose

[`examples/docker-compose.yaml`](examples/docker-compose.yaml) starts a server and runs the configurator in order: change the password, then apply the config ([Try it locally](#try-it-locally) walks through it). [`examples/cluster/compose.yaml`](examples/cluster/compose.yaml) does the same for a primary and a secondary.

### Kubernetes

[`examples/k8s.yaml`](examples/k8s.yaml) runs the configurator as a Job against a Technitium server behind the `technitium` Service. Credentials come from the `technitium-credentials` Secret, with the keys `username`, `password` and `new_password`; the example fills it with the [External Secrets Operator](https://external-secrets.io/), but any Secret with those keys works. The init containers change the password and then store an API token in the `technitium-api-token` Secret in the Job's namespace, for other workloads (see [API tokens](#api-tokens)); the main container applies the config from the ConfigMap. Every step is safe to re-run.

- **Re-running.** A Job runs once, and its pod template cannot be changed. To apply an edited config, delete the Job and apply it again. Under Argo CD, annotate it as a `Sync` hook with `hook-delete-policy: BeforeHookCreation` (commented in the example) so that every sync re-runs it.
- **Secrets in the config.** The example keeps a TSIG key in a ConfigMap to stay short. If the DNS config contains secrets (TSIG keys, user passwords, app credentials), mount it from a Secret instead.
- **RBAC.** The Role lets the Job read and update one Secret by name. Kubernetes cannot limit `create` to a name, so a second rule allows creating Secrets in the namespace; pre-create the Secret and drop that rule to avoid it.

### Without Docker

```bash
go install github.com/ashtonian/technitium-configurator/v3@v3.1.0
```

Needs Go 1.26 or later. The binary takes the same commands, flags and environment variables as the image.

## API tokens

`configure`, `export` and `cluster-state` log in with a username and password, or use an API token from `DNS_API_TOKEN` or the file `DNS_API_TOKEN_FILE` names. You do not need a token to use this tool. `create-token` makes one so that later runs, or other tools (a script, a dashboard, an ACME DNS plugin), work without the admin password.

It logs in with a username and password and needs a destination: a file (`DNS_TOKEN_PATH`), a Kubernetes Secret (`DNS_K8S_SECRET_NAME`), or both. If a destination already holds a token, the server is asked whether it still accepts it for this user. A valid token is reused and copied to any destination missing it; an invalid one, for example after the server was redeployed with fresh storage, is replaced.

### In a file

Mount a directory, not a single file:

```bash
mkdir -p tokens
docker run --rm --user "$(id -u):$(id -g)" \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  -e DNS_TOKEN_PATH="/app/tokens/token.yaml" \
  -v "$(pwd)/tokens:/app/tokens" \
  ashtonian/technitium-configurator:3.1.0 create-token
```

```console
level=INFO msg="Created API token" user=admin tokenName=sdk-token
level=INFO msg="Saved API token to file" path=/app/tokens/token.yaml
```

A re-run logs `Stored API token is valid; reusing it`. The file is written with mode `0600`:

<!-- docs-test: not a DNS config -->
```yaml
username: admin
tokenName: sdk-token
token: <64 hexadecimal characters>
```

To use it with this tool, mount it and point `DNS_API_TOKEN_FILE` at it in place of the username and password:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_API_TOKEN_FILE="/app/tokens/token.yaml" \
  -v "$(pwd)/tokens:/app/tokens:ro" \
  -v "$(pwd)/dns:/app/dns:ro" \
  ashtonian/technitium-configurator:3.1.0 configure /app/dns
```

`DNS_API_TOKEN_FILE` also takes a file holding only the token, as a Kubernetes Secret or Docker secret mounted as a file holds it.

### In a Kubernetes Secret

Run `create-token` in a pod whose service account may write the Secret: the `create-token` init container and the Role in [`examples/k8s.yaml`](examples/k8s.yaml) do this. Set `DNS_K8S_SECRET_NAME`; the Secret goes in the pod's own namespace under the key `api-token` unless `DNS_K8S_SECRET_NAMESPACE` or `DNS_K8S_SECRET_KEY` say otherwise.

```console
level=INFO msg="Created API token" user=admin tokenName=sdk-token
level=INFO msg="created secret" namespace=dns name=technitium-api-token
level=INFO msg="Saved API token to Kubernetes secret" namespace=dns name=technitium-api-token
```

To use the token in another pod, mount the Secret as a volume and set `DNS_API_TOKEN_FILE` to its key's file, for example `/etc/technitium/api-token`.

Outside a cluster, the [binary](#without-docker) finds the cluster and the namespace the way `kubectl` does: `KUBECONFIG`, then `~/.kube/config`, and the current context's namespace.

## Reference

### Commands

| Command | Description |
|---|---|
| `configure [path...]` | Apply DNS config files. A path may be a file or a directory (its `*.yaml` and `*.yml` files, in name order). Without a path, `DNS_CONFIG_PATH` is used, then the client config file's `config_path`, then `config.yaml` |
| `export [file]` | Write the server's configuration as a DNS config file, to stdout or to `file` (mode `0600`) |
| `create-token` | Create an API token, or keep a stored one the server still accepts, and save it to a file and/or a Kubernetes Secret ([API tokens](#api-tokens)) |
| `change-password` | Change the password. Succeeds without changes when the new password already works |
| `cluster-state` | Print the cluster state as YAML to stdout: whether the server is in a cluster, its domain and timing options, and each node's type, state, version, addresses and last sync |
| `version` | Print the version, commit and build date |

Flags go after the command: `technitium-configurator configure --log-level debug dns.yaml`. Every command except `version` first waits up to `DNS_WAIT_TIMEOUT` for the server's `/api/status` to answer, so it can start alongside the server. Logs go to stderr; stdout carries only command output: `export`'s and `cluster-state`'s YAML, and `version`.

### Client configuration

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

### DNS config files

[`examples/config.yaml`](examples/config.yaml) is a complete, runnable reference. The top-level keys:

| Key | Type | Description |
|---|---|---|
| `recordPolicy` | `merge` or `replace` | Default [record policy](#record-policies) for the file. Default `merge` |
| `cluster` | object | Cluster init (`mode: primary`) or join (`mode: secondary`); see [Clusters](#clusters) |
| `dnsSettings` | object | Server settings, named as `/api/settings/set` names them; see [Settings](#settings) |
| `administration` | object | Groups, users and permissions; see [Administration](#administration) |
| `zones` | list | Zones; see [Zones](#zones) |
| `records` | list | Records; see [Records](#records) |
| `apps` | list | DNS Apps; see [DNS Apps](#dns-apps) |

#### Several files and documents

`configure` accepts any number of files and directories, and a file may hold several documents separated by `---`. They are merged into one config: zones, records, apps, groups, users and permissions are combined, while `recordPolicy`, `cluster` and each individual `dnsSettings` key may appear in only one place. A zone, app, group, user or TSIG key declared twice is an error, so nothing is silently overridden.

```bash
technitium-configurator configure base.yaml zones/
```

### Settings

`dnsSettings` takes any key from `/api/settings/set`. A key you leave out is not sent. An explicit value is always sent, including `false`, `0`, `""` and `[]`; for example `forwarders: []` clears the forwarders.

Some settings depend on others, and the server resolves them in ways a file does not show, so validation enforces them:

- `forwarderProtocol` is required when `forwarders` is non-empty; otherwise the server resets the protocol to `Udp`.
- `enableCachePrefetch: true` with `cachePrefetchTrigger: 0` is rejected; the server would reset the trigger to 9.
- A `proxyType` other than `None` needs `proxyAddress` and `proxyPort`, and replaces the whole proxy, credentials included.
- On a cluster, `dnsServerDomain` must end with the cluster domain.

`tsigKeys` lists your keys. The cluster's own key (named after the cluster catalog) is kept automatically, and keys you remove from the file stay on the server. Each key needs `keyName`, `algorithmName` (`hmac-sha256`, `hmac-sha512` and the other HMAC names the server knows) and a base64 `sharedSecret`; an empty secret would make the server generate a new one on every run.

Changing a web-service setting (`webServiceHttpPort`, `webServiceTlsPort`, `webServiceLocalAddresses`, TLS, HTTP/3, Unix sockets) restarts the web service. The run waits for it to come back; if the change moved it away from `DNS_API_URL`, the run stops and asks you to re-run against the new address.

`enableDnsOverQuic` and `webServiceEnableHttp3` need `libmsquic` on the server. The official Docker image includes it; on other installs the server rejects the change.

### Zones

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

A Secondary zone transfers from its primaries when it is created, so they must be reachable from the DNS server:

```yaml
zones:
  - zone: "partner.example.net"
    type: "Secondary"
    primaryNameServerAddresses: ["192.0.2.10"]
    zoneTransferProtocol: "Tcp"
```

### Records

Every record has `domain` (or its alias `name`) and `type`, plus optionally `zone`, `ttl`, `comments`, `expiryTtl` and `recordPolicy`. A record is placed in the closest zone on the server that contains its name, so `www.example.com` lands in `example.com`, or in `www.example.com` if that zone exists; set `zone` to choose explicitly. [Records of each common type](#records-of-each-common-type) shows one of each.

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

### Administration

[A read-only user for monitoring](#a-read-only-user-for-monitoring) shows the shape.

- Groups and users are created if absent. A user needs `password`, `passwordFile` or `passwordEnv` only when the run has to create it, and the source is read only then, so it may be gone on later runs. The password is never compared or changed afterwards.
- `displayName`, `disabled`, `sessionTimeoutSeconds` and `description` are applied when set.
- `groups` on a user adds memberships; existing memberships the file does not name are kept.
- `permissions` sets the listed grants for a section (`Dashboard`, `Zones`, `Cache`, `Allowed`, `Blocked`, `Apps`, `DnsClient`, `Settings`, `DhcpServer`, `Administration`, `Logs`) and keeps every other grant, including the built-in Administrators. Access values are `view`, `modify` and `delete`. Every user and group named must exist on the server or be declared in the file; the server silently drops grants for unknown names, so the run fails instead, and it checks that the server kept every grant it sent.
- Per-zone permissions, SSO and LDAP are not managed.

### Clusters

Add a `cluster` section and `configure` applies it after the settings and before everything else. Only the primary needs settings, zones and records; secondaries need only the `cluster` section. [A two-node cluster](#a-two-node-cluster) shows both files. The full set of cluster fields:

```yaml
# primary
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
# secondary
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

### DNS Apps

Any app from the Technitium App Store, or any app package URL, can be installed. [Block ads and trackers](#block-ads-and-trackers) shows a complete app config.

```yaml
apps:
  - name: "NO DATA"
    url: "https://download.technitium.com/dns/apps/NoDataApp-v6.zip"
```

- `config` is converted to JSON and passed to the app, so every field the app accepts can be used. YAML merge keys (`<<`) are resolved; duplicate keys (including a second `<<` in one mapping: merge several with `<<: [*a, *b]`) and aliases that contain themselves are errors. Give the **complete** document: apps reject a config with missing keys. Start from the app's `dnsApp.config` in the [Technitium source](https://github.com/TechnitiumSoftware/DnsServer/tree/master/Apps).
- Leave `config` out to keep the app's current config. Apps used only through APP records (NO DATA, Auto PTR, Wild IP and others) need none.
- Config is written only when it differs from the stored config, compared as JSON; comments in the stored config are ignored, as the apps ignore them. Numbers keep every digit in any YAML spelling, so 64-bit integers and long decimals are passed exactly.
- `url` is needed only to install the app. An installed app is not downloaded again; app upgrades and uninstalls are not performed.
- Package URLs and the server versions they need are in the App Store catalogue, [`Apps/apps2.json`](https://github.com/TechnitiumSoftware/DnsServer/blob/master/Apps/apps2.json). For v15.6: Advanced Blocking `AdvancedBlockingApp-v11.2.1.zip`, Advanced Forwarding `AdvancedForwardingApp-v5.2.zip`.
- Apps that answer through APP records (Split Horizon, Geo, Failover, Weighted Round Robin and others) are configured with `type: APP` records. Apps are installed before APP records and every other record type except FWD.

### Export

Applying an export to the server it came from changes nothing. Applying it to a fresh server reproduces everything the export holds, once you add a password source for each user (passwords cannot be read back) and a `url` for every app the export left without one: apps that are not in the App Store, or every app when the App Store could not be read. An exported `url` is the store's current package, which the header notes when it is newer than the installed version. Cluster membership is not exported, so set the `cluster` section up separately. `export` loads its own output before writing it and refuses to write a file that would not load.

The export contains secrets: TSIG keys, FWD and global proxy credentials, and app configs. It leaves out:

- what the server maintains itself: SOA and apex NS records, DNSSEC records, internal zones;
- the cluster: the `cluster` section, the cluster catalog zone, the cluster's TSIG key, and zones provisioned by secondary catalogs;
- disabled records, user passwords, and certificate passwords the server masks.

Its header summarizes what it found on this server and left out: per zone, how many records were skipped and why (disabled, or a value the configurator cannot write), plus apps without a `url` or with a newer package. The categories in the list above are left out without a note.

### Compatibility

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

go test -race ./...                  # unit tests, including every DNS config in this README and examples/
go test -tags e2e ./e2e              # needs Docker; starts Technitium 15.6.1 containers
```

The unit tests load every `yaml` block in this README and in `.github/DOCKERHUB.md`, and every DNS config under `examples/`, through the same loader and validation `configure` uses. A YAML block that is not a DNS config is marked with `<!-- docs-test: not a DNS config -->` on the line before it.

The e2e suite checks the values a fresh install ends up with; that an unchanged re-run writes nothing but settings and zone options; record policies and values the server stores in another form; PTR preservation; IDN names; ACL clearing; administration; export applied back to its server and restored onto a fresh one; a re-run authenticated with the token file `create-token` wrote; the binary's exit codes and output streams; and a two-node cluster in which zones replicate, a local zone stays local, and the secondary re-runs with its original credentials and with a token it no longer has.

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
| `read API token file …` or `API token file … holds no token` | Is the file mounted at that path and readable by user `65532`? Has `create-token` written it? | Fix the mount or path, or run `create-token` first |
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
| An edited ConfigMap is not applied in Kubernetes | Has the Job already completed? A Job runs once | Delete the Job and apply it again, or run it as an Argo CD sync hook ([Kubernetes](#kubernetes)) |

## Security

- **Credentials in transit.** The API token goes in an `Authorization: Bearer` header and passwords in POST bodies, never in URLs. Redirects are not followed. Use an `https://` URL when the server is not on a trusted network.
- **Credentials in logs.** Request and response bodies are never logged, connection errors name the API path instead of the URL, and a URL containing credentials is rejected. Conflict and stale-value messages leave out APP record data and proxy passwords.
- **Token storage.** The token file gets mode `0600` before the token is written. It is replaced atomically when its directory is writable; a file bind-mounted on its own or in a read-only directory is overwritten in place, and only if it can be made private. The Kubernetes Role is limited to one Secret, plus `create`, which cannot be limited by name.
- **Tokens in the environment.** A process's environment is visible to `docker inspect`, `/proc` and Kubernetes pod specs. Prefer `DNS_API_TOKEN_FILE`, with the file mounted from a secret, to `DNS_API_TOKEN`.
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
| `cmd/version.go` | What `version` prints: `-ldflags` values, completed from the module version and commit Go records in the binary |
| `cmd/configure.go` | One configure pass: checks before any change, then settings, cluster, administration, zones, FWD records, apps, other records |
| `pkg/technitium/client.go`, `errors.go`, `logging.go` | HTTP client, response envelope, typed errors, request logging |
| `pkg/technitium/config.go`, `validate.go` | DNS config schema, multi-file loading and merging, validation |
| `pkg/technitium/plan.go` | Decisions without I/O: catalogs, ACL overrides, record placement and plans, TSIG merging |
| `pkg/technitium/rdata.go`, `names.go`, `rrtypes.go` | Record value comparison and conversion; canonical DNS names and zone keys; the server's record type table |
| `pkg/technitium/dns_settings.go`, `zone.go`, `records.go`, `apps.go`, `cluster.go`, `admin.go` | API calls and types per area |
| `pkg/technitium/export.go` | `export`: reading a server back into the schema |
| `pkg/technitium/client_config.go`, `token_file.go` | Client configuration and its validation; reading the API token file |
| `pkg/technitium/docs_test.go` | Loads every DNS config in the README, the Docker Hub overview and `examples/` |
| `pkg/kube` | Kubernetes Secret storage for `create-token`, and the current namespace |
| `e2e/` | End-to-end tests against Technitium containers, and the built binary's exit codes |
| `examples/config.yaml` | Full DNS config reference |
| `examples/docker-compose.yaml` | One server, configured by Compose |
| `examples/cluster/` | Two-node cluster with Compose: `compose.yaml`, `primary.yaml`, `secondary.yaml` |
| `examples/k8s.yaml` | Kubernetes Job, RBAC and credentials |
| `.github/workflows/` | CI: test, e2e, image build and release (`docker.yml`); Docker Hub overview publishing (`dockerhub-description.yml`) |
| `.github/DOCKERHUB.md` | The Docker Hub overview; changes are published when they reach `main` |
