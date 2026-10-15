# API tokens

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [In a file](#in-a-file)
- [In a Kubernetes Secret](#in-a-kubernetes-secret)

`configure`, `export` and `cluster-state` log in with a username and password, or use an API token from `DNS_API_TOKEN` or the file `DNS_API_TOKEN_FILE` names. You do not need a token to use this tool. `create-token` makes one so that later runs, or other tools (a script, a dashboard, an ACME DNS plugin), work without the admin password.

It logs in with a username and password and needs a destination: a file (`DNS_TOKEN_PATH`), a Kubernetes Secret (`DNS_K8S_SECRET_NAME`), or both. If a destination already holds a token, the server is asked whether it still accepts it for this user. A valid token is reused and copied to any destination missing it; an invalid one, for example after the server was redeployed with fresh storage, is replaced.

## In a file

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

## In a Kubernetes Secret

Run `create-token` in a pod whose service account may write the Secret: the `create-token` init container and the Role in [`examples/k8s.yaml`](../examples/k8s.yaml) do this. Set `DNS_K8S_SECRET_NAME`; the Secret goes in the pod's own namespace under the key `api-token` unless `DNS_K8S_SECRET_NAMESPACE` or `DNS_K8S_SECRET_KEY` say otherwise.

```console
level=INFO msg="Created API token" user=admin tokenName=sdk-token
level=INFO msg="created secret" namespace=dns name=technitium-api-token
level=INFO msg="Saved API token to Kubernetes secret" namespace=dns name=technitium-api-token
```

To use the token in another pod, mount the Secret as a volume and set `DNS_API_TOKEN_FILE` to its key's file, for example `/etc/technitium/api-token`.

Outside a cluster, the [binary](running.md#without-docker) finds the cluster and the namespace the way `kubectl` does: `KUBECONFIG`, then `~/.kube/config`, and the current context's namespace.
