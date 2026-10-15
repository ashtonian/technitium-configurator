# Clusters

[Documentation](README.md) · [Quick start](../README.md#quick-start)

Add a `cluster` section and `configure` applies it after the settings and before everything else. Only the primary needs settings, zones and records; secondaries need only the `cluster` section. [A two-node cluster](recipes.md#a-two-node-cluster) shows both files. The full set of cluster fields:

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
