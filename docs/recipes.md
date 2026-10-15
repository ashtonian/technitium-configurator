# Recipes

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Forward queries upstream over DNS-over-TLS](#forward-queries-upstream-over-dns-over-tls)
- [Send one domain to another DNS server](#send-one-domain-to-another-dns-server)
- [Let external-dns manage a zone (RFC 2136)](#let-external-dns-manage-a-zone-rfc-2136)
- [Block ads and trackers](#block-ads-and-trackers)
- [Records of each common type](#records-of-each-common-type)
- [A read-only user for monitoring](#a-read-only-user-for-monitoring)
- [Split the config across files](#split-the-config-across-files)
- [A two-node cluster](#a-two-node-cluster)

Each recipe is a complete config file. Combine them by passing several files, or a directory, to `configure` ([Several files](configuration.md#several-files-and-documents)).

## Forward queries upstream over DNS-over-TLS

```yaml
dnsSettings:
  forwarders: ["cloudflare-dns.com (1.1.1.1)", "cloudflare-dns.com (1.0.0.1)"]
  forwarderProtocol: "Tls"
```

`forwarderProtocol` is required whenever `forwarders` is non-empty. `forwarders: []` clears them, and the server resolves recursively.

## Send one domain to another DNS server

A Forwarder zone answers its names by asking another server, for example an office or Active Directory DNS server:

```yaml
zones:
  - zone: "corp.example.com"
    type: "Forwarder"
    initializeForwarder: true
    protocol: "Udp"
    forwarder: "10.20.0.53"
```

## Let external-dns manage a zone (RFC 2136)

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

Updates and transfers without the key are refused. Records that external-dns writes are not in the file, and the default `merge` [record policy](run-semantics.md#record-policies) leaves them alone.

## Block ads and trackers

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

[`examples/config.yaml`](../examples/config.yaml) also configures Advanced Forwarding. See [DNS Apps](apps.md#dns-apps) for finding an app's package URL and config.

## Records of each common type

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

A record goes into the closest zone that contains its name. Without `ttl`, the server's `defaultRecordTtl` applies. Every type and field is in [Records](configuration.md#records).

## A read-only user for monitoring

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

See [Administration](configuration.md#administration).

## Split the config across files

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

## A two-node cluster

[`examples/cluster`](../examples/cluster) runs this with Docker Compose. The primary file holds the whole DNS config; the secondary only joins:

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

Configure the primary first, then each secondary. See [Clusters](clusters.md#clusters) for credentials, replication and catalog ACLs.
