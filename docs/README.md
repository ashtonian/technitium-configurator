# Documentation

[Quick start](../README.md#quick-start) · [Docker image](https://hub.docker.com/r/ashtonian/technitium-configurator) · [Releases](https://github.com/ashtonian/technitium-configurator/releases)

## Overview

DNS is critical, so its configuration should be repeatable. Technitium stores its configuration in binary files, and there is no declarative way to manage it; this tool fills that gap through Technitium's HTTP API.

- **Bootstrap, then re-run safely.** Zones, records, apps, groups and users are created when absent. Settings, zone options and the primary's cluster timing options are sent on every run; app config is written when it differs. Nothing is pruned: what the file leaves out stays on the server.
- **Every v15.6 server setting.** All 131 keys `/api/settings/set` accepts. Explicit `false`, `0`, `""` and `[]` are applied.
- **Zones and records.** All zone types, including the root zone, with ACLs, update policies and catalog membership. Every record type the API has fields for, and other types as hex RDATA, with a [record policy](run-semantics.md#record-policies) that chooses between adding values and replacing them.
- **Any DNS App.** Install from a package URL and pass its config through as JSON.
- **Clusters.** Initialize a primary or join a secondary; zones on the primary replicate through the cluster catalog.
- **Users, groups and permissions**, created if absent and merged into the existing grants.
- **Export.** Write a server's configuration as a config file you can edit and apply again.
- **Checked before anything changes.** Unknown keys and invalid values fail the run before the first change. Problems only the server can find fail that item, and every failure makes the run exit non-zero.
- **Quiet re-runs.** Records, apps, users, groups and permissions are compared with the server in the form it stores them, and nothing that matches is sent again.

Requires **Technitium DNS Server v15.6.0 or later**; see [Compatibility](compatibility.md#compatibility).

## Getting started

- [Set up a server or use an existing one](getting-started.md): local Compose demo, password setup and applying a config.
- [Deployment](running.md): Docker, Compose, Kubernetes Jobs and native installation.
- [API tokens](api-tokens.md): create and reuse a token file or Kubernetes Secret.
- [Export and restore](export.md): start from a running server and prepare an export for a fresh one.

## Configuration and recipes

- [Recipes](recipes.md): DNS-over-TLS, conditional forwarding, external-dns, blocking, records, users, split files and clusters.
- [Configuration schema](configuration.md): files, settings, zones, records and administration.
- [DNS Apps](apps.md): packages, complete app configs and APP records.
- [Clusters](clusters.md): primary and secondary configuration, credentials, replication and catalog ACLs.

## Reference

- [Command-line reference](cli-reference.md): commands, flags, environment variables and client configuration.
- [Run semantics](run-semantics.md): existing resources, record policies, validation, ordering and exit codes.
- [Compatibility and limitations](compatibility.md): supported servers, scope, dependencies and interfaces.
- [Operations and security](operations.md): logs, troubleshooting, credentials and secrets.
- [Contributing](../CONTRIBUTING.md): build, tests, release workflow and code map.
