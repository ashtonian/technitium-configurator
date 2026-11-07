# Continuous reconciliation

`reconcile [path...]` runs the same configuration pass as `configure`, then
waits for `DNS_RECONCILE_INTERVAL` (default one minute). It reloads the DNS
files and any mounted API token on every pass. Mount a configuration directory
rather than a Kubernetes `subPath` file when Secret updates should propagate.
Client options and password environment variables are process configuration;
restart the process when they change.

Each pass has `DNS_RECONCILE_TIMEOUT` (default five minutes), and every HTTP
call retains `DNS_TIMEOUT`. Transient server errors and invalid mounted DNS
configuration are logged and retried after the interval. Invalid client
options fail at startup. SIGINT and SIGTERM cancel active requests and the
interval wait; owned login-session cleanup is additionally bounded by
`DNS_TIMEOUT`. Caller-supplied API tokens are never revoked.

Use one reconciler per server. Do not run competing reconcilers with different
desired configurations. A successful process start does not establish that a
pass succeeded: monitor `Configuration complete` and `Reconciliation failed`
logs and validate DNS answers, zone serials and cluster synchronization.
Settings and zone options are applied each pass, while records, apps and users
retain the [normal configure semantics](run-semantics.md).

For first boot, password authentication can supply `DNS_PASSWORD` (the image's
initial password) and `DNS_NEW_PASSWORD` (the intended password). The pass uses
the intended password when it already works, or changes the initial password
before applying configuration. `DNS_WAIT_TIMEOUT` lets the reconciler start
alongside the server.

For clustered containers, use `cluster.nodeIPs: auto` in each node's file.
The reconciler reads that server's current interfaces and updates native
membership, so transfer ACLs and NOTIFY destinations follow replacements.
Leave the native catalog's policy to Technitium; use explicit member-zone
overrides for external transfer readers, preserving the cluster's TSIG key.
See [clusters](clusters.md).

```sh
DNS_API_URL=http://dns-server:5380 \
DNS_API_TOKEN_FILE=/run/secrets/dns-token \
DNS_RECONCILE_INTERVAL=1m \
technitium-configurator reconcile /app/dns/
```
