# Technitium Configurator

[![Build](https://github.com/ashtonian/technitium-configurator/actions/workflows/docker.yml/badge.svg)](https://github.com/ashtonian/technitium-configurator/actions/workflows/docker.yml)
[![Docker Image](https://img.shields.io/docker/v/ashtonian/technitium-configurator?sort=semver&label=docker)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Docker Pulls](https://img.shields.io/docker/pulls/ashtonian/technitium-configurator)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Docker Image Size](https://img.shields.io/docker/image-size/ashtonian/technitium-configurator/latest)](https://hub.docker.com/r/ashtonian/technitium-configurator)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ashtonian/technitium-configurator)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Configure a [Technitium DNS Server](https://technitium.com/dns/) from YAML:
settings, zones, records, apps, users and clusters. Apply the same files
again as your configuration changes, or export a running server to YAML.

Requires **Technitium DNS Server v15.6.0 or later**. Docker images support
`linux/amd64` and `linux/arm64`; [native installation](docs/running.md#without-docker)
needs Go 1.26 or later. See [compatibility](docs/compatibility.md).

## Why use it

- **Repeatable setup.** Create missing resources and apply the settings
  you list; omitted resources stay on the server.
- **Checked before changes.** Unknown keys and invalid values fail
  validation before configuration is applied.
- **Flexible configuration.** Split YAML across files, configure DNS
  Apps, initialize or join clusters and export existing servers.
- **Automation-friendly.** Run from a shell, Docker Compose, CI or a
  Kubernetes Job, with non-zero exit codes when operations fail.

[Run semantics](docs/run-semantics.md) explains existing-resource behavior,
record replacement and partial failures; [limitations](docs/compatibility.md#limitations)
defines what the tool manages.

## Quick start

For an existing server, save this as `dns.yaml`:

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

Apply it with the server's web-service URL and current admin password:

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="your-admin-password" \
  -v "$(pwd)/dns.yaml:/app/dns.yaml:ro" \
  ashtonian/technitium-configurator:3.1.0 configure /app/dns.yaml
```

The equivalent CLI command and output, including a second run:

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

Log timestamps are trimmed here. `applied` counts settings and zone
options, which are sent on every run. Records already matching the
configuration are left unchanged. See [setup with your server](docs/getting-started.md#use-it-with-your-server)
for changing the default password and [API tokens](docs/api-tokens.md)
for token-based authentication.

## Try it locally

With Docker installed, start a disposable Technitium server and apply
the sample config:

```bash
git clone https://github.com/ashtonian/technitium-configurator.git
cd technitium-configurator/examples
docker compose up -d
docker compose wait configurator-configure
docker compose logs --no-log-prefix configurator-password configurator-configure
```

The demo serves DNS on `127.0.0.1:1053` and its web console on
<http://localhost:5380> (`admin` / `securepassword`). See the
[local walkthrough](docs/getting-started.md#try-it-locally) for queries,
re-runs and cleanup, or [the two-node cluster example](examples/cluster/).

## Documentation

| Task | Guide |
|---|---|
| Set up a server and apply YAML | [Getting started](docs/getting-started.md) |
| Deploy with Docker, Compose or Kubernetes | [Running it](docs/running.md) |
| Find commands, flags and environment variables | [CLI reference](docs/cli-reference.md) |
| Configure settings, zones, records and users | [Configuration reference](docs/configuration.md) |
| Use forwarding, blocking, external-dns or split files | [Recipes](docs/recipes.md) |
| Configure apps or clusters | [DNS Apps](docs/apps.md), [clusters](docs/clusters.md) |
| Create API tokens or export a server | [API tokens](docs/api-tokens.md), [export and restore](docs/export.md) |
| Understand changes, failures and troubleshooting | [Run semantics](docs/run-semantics.md), [operations and security](docs/operations.md) |
| Check support or contribute | [Compatibility and limitations](docs/compatibility.md), [contributing](CONTRIBUTING.md) |

See the [documentation index](docs/README.md) and the complete
[example configuration](examples/config.yaml).

## License

[MIT](LICENSE).
