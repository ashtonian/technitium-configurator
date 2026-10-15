# Export and restore

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Start from a server you already run](#start-from-a-server-you-already-run)
- [Export](#export)

## Start from a server you already run

`export` writes a server's configuration as a config file. Applying it back to the same server changes nothing, so it is a safe starting point to put under version control:

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:3.1.0 export > dns/config.yaml
```

```yaml
# Exported by technitium-configurator from http://dns-server:5380.
# It contains secrets (TSIG keys, proxy and app credentials): keep it private.
# - Users are exported without passwords. Add password, passwordFile or passwordEnv to any user the file must be able to create.
dnsSettings:
  dnsServerDomain: dns.home.arpa
  dnsServerLocalEndPoints:
    - 0.0.0.0:53
    - '[::]:53'
  defaultRecordTtl: 3600
  # (trimmed: an export lists every server setting)
zones:
  - zone: home.arpa
    type: Primary
    aclSettings:
      queryAccess: Allow
      zoneTransfer: AllowOnlyZoneNameServers
      notify: ZoneNameServers
      update: Deny
records:
  - domain: files.home.arpa
    type: CNAME
    zone: home.arpa
    ttl: 3600
    cname: nas.home.arpa
  - domain: nas.home.arpa
    type: A
    zone: home.arpa
    ttl: 3600
    ipAddress: 192.168.1.10
```

An export lists all of the roughly 130 server settings. Delete the ones you do not want to manage: a setting left out of the file is not sent. See [Export](#export) for what an export leaves out and what it needs before it can rebuild a fresh server.

## Export

Applying an export to the server it came from changes nothing. Applying it to a fresh server reproduces everything the export holds, once you add a password source for each user (passwords cannot be read back) and a `url` for every app the export left without one: apps that are not in the App Store, or every app when the App Store could not be read. An exported `url` is the store's current package, which the header notes when it is newer than the installed version. Cluster membership is not exported, so set the `cluster` section up separately. `export` loads its own output before writing it and refuses to write a file that would not load.

The export contains secrets: TSIG keys, FWD and global proxy credentials, and app configs. It leaves out:

- what the server maintains itself: SOA and apex NS records, DNSSEC records, internal zones;
- the cluster: the `cluster` section, the cluster catalog zone, the cluster's TSIG key, and zones provisioned by secondary catalogs;
- disabled records, user passwords, and certificate passwords the server masks.

Its header summarizes what it found on this server and left out: per zone, how many records were skipped and why (disabled, or a value the configurator cannot write), plus apps without a `url` or with a newer package. The categories in the list above are left out without a note.
