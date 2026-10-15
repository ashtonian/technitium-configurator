# Running it

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Docker](#docker)
- [Docker Compose](#docker-compose)
- [Kubernetes](#kubernetes)
- [Without Docker](#without-docker)

## Docker

```bash
docker pull ashtonian/technitium-configurator:3.1.0
```

Images are published for `linux/amd64` and `linux/arm64`. The image is built `FROM scratch` with a CA bundle and the static binary at `/technitium-configurator`. It runs as user `65532`, so a host directory the tool writes to must be writable by that user, or pass `--user "$(id -u):$(id -g)"`. Its working directory is `/app`, so a relative `config.yaml` resolves to `/app/config.yaml`.

## Docker Compose

[`examples/docker-compose.yaml`](../examples/docker-compose.yaml) starts a server and runs the configurator in order: change the password, then apply the config ([Try it locally](getting-started.md#try-it-locally) walks through it). [`examples/cluster/compose.yaml`](../examples/cluster/compose.yaml) does the same for a primary and a secondary.

## Kubernetes

[`examples/k8s.yaml`](../examples/k8s.yaml) runs the configurator as a Job against a Technitium server behind the `technitium` Service. Credentials come from the `technitium-credentials` Secret, with the keys `username`, `password` and `new_password`; the example fills it with the [External Secrets Operator](https://external-secrets.io/), but any Secret with those keys works. The init containers change the password and then store an API token in the `technitium-api-token` Secret in the Job's namespace, for other workloads (see [API tokens](api-tokens.md#api-tokens)); the main container applies the config from the ConfigMap. Every step is safe to re-run.

- **Re-running.** A Job runs once, and its pod template cannot be changed. To apply an edited config, delete the Job and apply it again. Under Argo CD, annotate it as a `Sync` hook with `hook-delete-policy: BeforeHookCreation` (commented in the example) so that every sync re-runs it.
- **Secrets in the config.** The example keeps a TSIG key in a ConfigMap to stay short. If the DNS config contains secrets (TSIG keys, user passwords, app credentials), mount it from a Secret instead.
- **RBAC.** The Role lets the Job read and update one Secret by name. Kubernetes cannot limit `create` to a name, so a second rule allows creating Secrets in the namespace; pre-create the Secret and drop that rule to avoid it.

## Without Docker

```bash
go install github.com/ashtonian/technitium-configurator/v3@v3.1.0
```

Needs Go 1.26 or later. The binary takes the same commands, flags and environment variables as the image.
