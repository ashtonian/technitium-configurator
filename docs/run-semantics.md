# How a run works

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Record policies](#record-policies)
- [Validation](#validation)
- [Order](#order)
- [Exit codes](#exit-codes)

| Section | Every run | When it already exists |
|---|---|---|
| `dnsSettings` | Sends exactly the keys in the file, on every run. Keys you leave out are not sent; a few settings that the server treats as a unit are reset together (see [Settings](configuration.md#settings)) | — |
| `zones` | Creates missing zones, then sends their options and ACLs, on every run | Creation is skipped; options are still sent. A zone of a different type is reported as a conflict and left alone |
| `records` | Adds missing values (see [record policies](#record-policies)) | An identical record is not sent again; values are compared in the form the server stores them |
| `apps` | Installs missing apps; writes `config` when it differs from the stored config | Installation is skipped. Leave `config` out to keep the app's own |
| `administration` | Creates missing groups and users; applies descriptions, display names, disabled state, session timeouts, group membership and permissions | Membership and permissions are merged: groups and grants the file does not name are kept. Passwords are only set when a user is created |
| `cluster` | Applies the node IPs and the primary's timing options | Initialization or join happens once |

Nothing is pruned. Removing a zone, record, app, group or user from the file leaves it on the server. The one exception is `recordPolicy: replace`, which removes the other values of a name and type the file declares.

Settings and zone options are sent on every run because the server applies them in one idempotent call each; a re-run that sends them changes nothing. Everything else is compared first, and an unchanged re-run writes no record, zone, app, user, group or permission.

## Record policies

`recordPolicy` decides what happens when a name and type already have values on the server. Set it for the whole file, override it per zone, and override that per record.

Say the file declares `nas.home.arpa A 192.168.1.10`, and someone added `192.168.1.99` for the same name in the web console. With `merge`, the default, the run leaves the extra value and says so:

```console
level=INFO msg="Record values on the server that the config does not list; left in place (recordPolicy: replace removes them)" item="record nas.home.arpa A" values=[192.168.1.99]
```

With `recordPolicy: "replace"` on that record, the file owns the name and type, and the server ends up with only `192.168.1.10`:

```console
level=INFO msg="Replaced records" item="record nas.home.arpa A" values=1
```

| Policy | Use it for |
|---|---|
| `merge` (default) | Zones you share with other writers, such as external-dns, DHCP or the web console |
| `replace` | Names the file owns completely |

Under `merge`, a CNAME, DNAME or APP record that exists with a different value is reported as a conflict and left alone, because a name can hold only one of them. A PTR created by an earlier run or by hand is never overwritten under `merge`. The TTL, comments and expiry of a value that already exists are not changed.

Under `replace`, the declared values are compared with the server first, and nothing is written when they already match, including the TTL, comments, expiry TTL and NS glue the file sets. When they differ, the set is rewritten, `ptr: true` included. A name with several values briefly has fewer while the run writes them.

## Validation

Checks happen in three stages:

1. **Loading the files.** A YAML syntax error, an unknown key or a key set in two files stops loading at once. After that, every problem that can be judged from the files alone is reported together: missing required fields, values outside the server's ranges, unknown enum values (including ones the server would silently ignore, such as zone ACL options), malformed addresses, endpoints, networks and name server addresses, DS, SSHFP and TLSA digests whose length does not match their digest type, and contradictory combinations. TTLs are limited to 2147483647, the RFC 2181 maximum, although the server stores larger values. App `config` blocks are checked only for being representable as JSON, since their keys belong to each app. Each error names the file and document it came from.
2. **Before any change.** The run reads the server's zones and places every record. A record no zone contains, a record naming a zone that does not exist, two values for a CNAME, DNAME or APP name, records of one name and type with different policies, an FWD record outside a Forwarder zone, and cluster timing options the server would reject all stop the run with nothing changed.
3. **During the run.** Some problems only the server can find, such as an app config the app rejects, a missing reverse zone for `ptr: true`, or QUIC without `libmsquic`. These fail that item, or stop the run when they happen in settings or the cluster.

[The setup walkthrough](getting-started.md#3-apply-it) shows an error from each of the first two stages.

## Order

Settings, cluster, administration, zones (catalog zones first), FWD records, apps, then the other records. FWD records come before apps because they decide how the server resolves the App Store's address; the other records come last so that a record can refer to an app or zone declared in the same file.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, or help was asked for (`help`, `--help`, `<command> --help`). Conflicts are logged as warnings and do not change the code |
| `1` | The config is invalid, a prerequisite (settings, cluster, login) failed, or at least one operation failed. The run continues past individual failures and lists every one at the end |
| `2` | Bad command-line usage: no command, an unknown command, an unknown flag, or too many arguments (`version` and `help` take none). The error and the usage text go to stderr |
