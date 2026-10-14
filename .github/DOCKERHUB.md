# Technitium Configurator

Sets up a [Technitium DNS Server](https://technitium.com/dns/) from YAML files. Run it against a fresh server to configure it, then run it again as often as you like: it creates what is missing, applies the settings you list, and leaves everything else alone.

It also changes the admin password, creates API tokens (stored in a file or a Kubernetes Secret), initializes or joins DNS clusters, and exports a running server's configuration as YAML.

Source, full documentation and examples: **[github.com/ashtonian/technitium-configurator](https://github.com/ashtonian/technitium-configurator)**

## Tags

| Tag | What it is |
|---|---|
| `latest` | The newest stable release |
| `X.Y.Z`, `vX.Y.Z` | A release, for example `3.1.0` |
| `X.Y.Z-rc.N` | Release candidates; `latest` never points to one |
| `beta`, `beta-<date>-<sha>` | Builds of the `main` branch |

Images are published for `linux/amd64` and `linux/arm64`, with build provenance and an SBOM. Version 3 requires **Technitium DNS Server v15.6.0 or later**; see the [release notes](https://github.com/ashtonian/technitium-configurator/releases) for what changed.

## What it does

- **Bootstrap, then re-run safely.** Zones, records, apps, groups and users are created when absent. Settings and zone options are applied on every run. Nothing is pruned.
- **Every v15.6 server setting**, with explicit `false`, `0`, `""` and `[]` applied.
- **Zones and records.** All zone types with ACLs, update policies and catalog membership. A record policy chooses between adding values (`merge`) and making the file own the values of each name and type it declares (`replace`).
- **Any DNS App.** Install from a package URL and pass its config through as JSON.
- **Clusters.** Initialize a primary or join a secondary; zones on the primary replicate through the cluster catalog.
- **Users, groups and permissions**, created if absent and merged into the existing grants.
- **Export** a running server as a config file you can edit and apply again.
- **Strict.** Unknown keys and invalid values in the files fail before anything changes; problems only the server can find fail that item, and every failure makes the run exit non-zero.

## Quick start

Change the default password. Safe to re-run:

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="admin" \
  -e DNS_NEW_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:3.1.0 change-password
```

Write a DNS config:

```yaml
# dns/config.yaml
dnsSettings:
  dnsServerDomain: "dns.example.com"
  forwarders: []
zones:
  - zone: "example.com"
    type: "Primary"
records:
  - domain: "www.example.com"
    type: "A"
    ipAddress: "192.0.2.10"
```

Apply it. Every later run changes nothing that is already in place:

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  -v "$(pwd)/dns:/app/dns:ro" \
  ashtonian/technitium-configurator:3.1.0 configure /app/dns
```

Export a running server:

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:3.1.0 export > dns.yaml
```

The commands above need no API token. To give one to another tool, so that it does not need the password, create it in a mounted directory. Running as your own user lets the image write there:

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

Other commands take it with `-e DNS_API_TOKEN_FILE=/app/tokens/token.yaml` and the same mount. Storing the token in a Kubernetes Secret from inside a cluster is in [API tokens](https://github.com/ashtonian/technitium-configurator#api-tokens).

## Docker Compose

Start a server and configure it in order: change the password, then apply the config.

<!-- docs-test: not a DNS config -->
```yaml
services:
  dns:
    image: technitium/dns-server:15.6.1
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "5380:5380/tcp"
    environment:
      - DNS_SERVER_DOMAIN=dns.example.com
      - DNS_SERVER_ADMIN_PASSWORD=changeme
    volumes:
      - dns-data:/etc/dns
    healthcheck:
      test: ["CMD-SHELL", "curl -fs http://127.0.0.1:5380/api/dnsClient/healthCheck | grep -q '\"status\":\"ok\"'"]
      interval: 10s
      retries: 6

  configurator-password:
    image: ashtonian/technitium-configurator:3.1.0
    environment:
      - DNS_API_URL=http://dns:5380
      - DNS_USERNAME=admin
      - DNS_PASSWORD=changeme
      - DNS_NEW_PASSWORD=securepassword
    depends_on:
      dns:
        condition: service_healthy
    command: change-password

  configurator-configure:
    image: ashtonian/technitium-configurator:3.1.0
    environment:
      - DNS_API_URL=http://dns:5380
      - DNS_USERNAME=admin
      - DNS_PASSWORD=securepassword
    volumes:
      - ./config.yaml:/app/config.yaml:ro
    depends_on:
      configurator-password:
        condition: service_completed_successfully
    command: configure /app/config.yaml

volumes:
  dns-data:
```

A two-node cluster example and a Kubernetes Job with RBAC for token storage are in [`examples/`](https://github.com/ashtonian/technitium-configurator/tree/main/examples).

## Commands

| Command | Description |
|---|---|
| `configure [path...]` | Apply DNS config files or directories |
| `export [file]` | Write the server's configuration as a DNS config file |
| `create-token` | Create an API token, or keep a stored one the server still accepts |
| `change-password` | Change the password; succeeds without changes when the new one already works |
| `cluster-state` | Show the cluster's nodes, state, versions and last sync |
| `version` | Print the version, commit and build date |

## Main environment variables

| Variable | Default | Description |
|---|---|---|
| `DNS_API_URL` | (required) | Technitium web service, for example `http://dns-server:5380` |
| `DNS_API_TOKEN` | | API token; used instead of username and password |
| `DNS_API_TOKEN_FILE` | | File holding the API token, such as the one `create-token` writes |
| `DNS_USERNAME`, `DNS_PASSWORD` | | Login, and the current password for `change-password` |
| `DNS_NEW_PASSWORD` | | New password for `change-password` |
| `DNS_CONFIG_PATH` | `config.yaml` | DNS config file or directory when `configure` is given no path |
| `DNS_TOKEN_PATH` | | Token file `create-token` writes (mode `0600`) |
| `DNS_K8S_SECRET_NAME` | | Kubernetes Secret `create-token` stores the token in, in the current namespace |
| `DNS_WAIT_TIMEOUT` | `60s` | How long to wait for the server to answer before starting |
| `DNS_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

All options, the DNS config schema and troubleshooting are in the [full documentation](https://github.com/ashtonian/technitium-configurator#readme).

## Image details

- Built `FROM scratch`: a static binary at `/technitium-configurator` and a CA bundle, nothing else.
- Runs as user `65532`; the working directory is `/app`, so a relative `config.yaml` resolves to `/app/config.yaml`.
- Logs go to stderr; stdout carries only command output: `export`'s and `cluster-state`'s YAML, and `version`.
- Exit codes: `0` success or help, `1` failure (every failure is listed), `2` bad command-line usage.

Issues and feature requests: [github.com/ashtonian/technitium-configurator/issues](https://github.com/ashtonian/technitium-configurator/issues)
