# Operations

[Documentation](README.md) · [Quick start](../README.md#quick-start)

**Health.** The tool is a run-to-completion command. Its exit code is the health signal: `0` on success, `1` when anything failed. In Kubernetes, a failed Job is the alert.

**Logs.** Text lines on stderr. A `configure` run that reaches its resources ends with `Configuration complete created=… applied=… unchanged=… conflicts=… failed=…`; a run that stops earlier (invalid config, records that cannot be placed, a settings or cluster failure) ends with `level=ERROR msg="Command failed"`. Failures are `level=ERROR msg=Failed item=…`, conflicts are `level=WARN`, and values that `merge` left in place are reported at `info`. At `debug`, every API call is logged with its method, path, non-secret query parameters, status and duration.

## Troubleshooting

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
| An edited ConfigMap is not applied in Kubernetes | Has the Job already completed? A Job runs once | Delete the Job and apply it again, or run it as an Argo CD sync hook ([Kubernetes](running.md#kubernetes)) |

# Security

- **Credentials in transit.** The API token goes in an `Authorization: Bearer` header and passwords in POST bodies, never in URLs. Redirects are not followed. Use an `https://` URL when the server is not on a trusted network.
- **Credentials in logs.** Request and response bodies are never logged, connection errors name the API path instead of the URL, and a URL containing credentials is rejected. Conflict and stale-value messages leave out APP record data and proxy passwords.
- **Token storage.** The token file gets mode `0600` before the token is written. It is replaced atomically when its directory is writable; a file bind-mounted on its own or in a read-only directory is overwritten in place, and only if it can be made private. The Kubernetes Role is limited to one Secret, plus `create`, which cannot be limited by name.
- **Tokens in the environment.** A process's environment is visible to `docker inspect`, `/proc` and Kubernetes pod specs. Prefer `DNS_API_TOKEN_FILE`, with the file mounted from a secret, to `DNS_API_TOKEN`.
- **Secrets in config.** TSIG secrets, proxy and app credentials and initial user passwords may appear in DNS config files and in `export` output; store them as secrets. Prefer `passwordEnv` or `passwordFile` to `password`.
- **Clusters.** `ignoreCertErrors` applies only to the join call; use it only on networks you trust.
- **Image.** `FROM scratch`, a pinned builder image, no shell, non-root user `65532`.
