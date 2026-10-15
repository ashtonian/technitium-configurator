# DNS config files

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Several files and documents](#several-files-and-documents)
- [Settings](#settings)
- [Zones](#zones)
- [Records](#records)
- [Administration](#administration)

[`examples/config.yaml`](../examples/config.yaml) is a complete, runnable reference. The top-level keys:

| Key | Type | Description |
|---|---|---|
| `recordPolicy` | `merge` or `replace` | Default [record policy](run-semantics.md#record-policies) for the file. Default `merge` |
| `cluster` | object | Cluster init (`mode: primary`) or join (`mode: secondary`); see [Clusters](clusters.md#clusters) |
| `dnsSettings` | object | Server settings, named as `/api/settings/set` names them; see [Settings](#settings) |
| `administration` | object | Groups, users and permissions; see [Administration](#administration) |
| `zones` | list | Zones; see [Zones](#zones) |
| `records` | list | Records; see [Records](#records) |
| `apps` | list | DNS Apps; see [DNS Apps](apps.md#dns-apps) |

## Several files and documents

`configure` accepts any number of files and directories, and a file may hold several documents separated by `---`. They are merged into one config: zones, records, apps, groups, users and permissions are combined, while `recordPolicy`, `cluster` and each individual `dnsSettings` key may appear in only one place. A zone, app, group, user or TSIG key declared twice is an error, so nothing is silently overridden.

```bash
technitium-configurator configure base.yaml zones/
```

## Settings

`dnsSettings` takes any key from `/api/settings/set`. A key you leave out is not sent. An explicit value is always sent, including `false`, `0`, `""` and `[]`; for example `forwarders: []` clears the forwarders.

Some settings depend on others, and the server resolves them in ways a file does not show, so validation enforces them:

- `forwarderProtocol` is required when `forwarders` is non-empty; otherwise the server resets the protocol to `Udp`.
- `enableCachePrefetch: true` with `cachePrefetchTrigger: 0` is rejected; the server would reset the trigger to 9.
- A `proxyType` other than `None` needs `proxyAddress` and `proxyPort`, and replaces the whole proxy, credentials included.
- On a cluster, `dnsServerDomain` must end with the cluster domain.

`tsigKeys` lists your keys. The cluster's own key (named after the cluster catalog) is kept automatically, and keys you remove from the file stay on the server. Each key needs `keyName`, `algorithmName` (`hmac-sha256`, `hmac-sha512` and the other HMAC names the server knows) and a base64 `sharedSecret`; an empty secret would make the server generate a new one on every run.

Changing a web-service setting (`webServiceHttpPort`, `webServiceTlsPort`, `webServiceLocalAddresses`, TLS, HTTP/3, Unix sockets) restarts the web service. The run waits for it to come back; if the change moved it away from `DNS_API_URL`, the run stops and asks you to re-run against the new address.

`enableDnsOverQuic` and `webServiceEnableHttp3` need `libmsquic` on the server. The official Docker image includes it; on other installs the server rejects the change.

## Zones

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
| `overrideCatalogQueryAccess`, `overrideCatalogZoneTransfer`, `overrideCatalogNotify` | catalog members | Use the zone's own ACLs instead of the catalog's; see [Clusters](clusters.md#clusters) |
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

## Records

Every record has `domain` (or its alias `name`) and `type`, plus optionally `zone`, `ttl`, `comments`, `expiryTtl` and `recordPolicy`. A record is placed in the closest zone on the server that contains its name, so `www.example.com` lands in `example.com`, or in `www.example.com` if that zone exists; set `zone` to choose explicitly. [Records of each common type](recipes.md#records-of-each-common-type) shows one of each.

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

## Administration

[A read-only user for monitoring](recipes.md#a-read-only-user-for-monitoring) shows the shape.

- Groups and users are created if absent. A user needs `password`, `passwordFile` or `passwordEnv` only when the run has to create it, and the source is read only then, so it may be gone on later runs. The password is never compared or changed afterwards.
- `displayName`, `disabled`, `sessionTimeoutSeconds` and `description` are applied when set.
- `groups` on a user adds memberships; existing memberships the file does not name are kept.
- `permissions` sets the listed grants for a section (`Dashboard`, `Zones`, `Cache`, `Allowed`, `Blocked`, `Apps`, `DnsClient`, `Settings`, `DhcpServer`, `Administration`, `Logs`) and keeps every other grant, including the built-in Administrators. Access values are `view`, `modify` and `delete`. Every user and group named must exist on the server or be declared in the file; the server silently drops grants for unknown names, so the run fails instead, and it checks that the server kept every grant it sent.
- Per-zone permissions, SSO and LDAP are not managed.
