# Getting started

[Documentation](README.md) · [Quick start](../README.md#quick-start)

- [Try it locally](#try-it-locally)
- [Use it with your server](#use-it-with-your-server)

Commands in these walkthroughs use the Docker image. For an existing
server, start at [Use it with your server](#use-it-with-your-server).

## Try it locally

Needs Docker. This starts a Technitium 15.6.1 server, changes its admin password and applies [`examples/config.yaml`](../examples/config.yaml): two zones, records with a reverse zone, a TSIG key, and the Advanced Blocking and Advanced Forwarding apps.

```bash
git clone https://github.com/ashtonian/technitium-configurator.git
cd technitium-configurator/examples
docker compose up -d
docker compose wait configurator-configure
docker compose logs --no-log-prefix configurator-password configurator-configure
```

```console
level=INFO msg="Password changed" user=admin
level=INFO msg="DNS settings applied"
level=INFO msg="Created zone" zone=example.com type=Primary
level=INFO msg="Created zone" zone=corp.internal type=Forwarder
level=INFO msg="Installed app" app="Advanced Blocking"
level=INFO msg="App config applied" app="Advanced Blocking"
level=INFO msg="Installed app" app="Advanced Forwarding"
level=INFO msg="App config applied" app="Advanced Forwarding"
level=INFO msg="Installed app" app="NO DATA"
level=INFO msg="Created record" domain=www.example.com type=A
level=INFO msg="Created record" domain=mail.example.com type=MX
level=INFO msg="Created record" domain=example.com type=TXT
level=INFO msg="Created record" domain=docs.example.com type=CNAME
level=INFO msg="Replaced records" item="record pool.example.com A" values=2
level=INFO msg="Configuration complete" created=9 applied=6 unchanged=0 conflicts=0 failed=0
```

The server answers on `127.0.0.1:1053`, and the web console is at <http://localhost:5380> (user `admin`, password `securepassword`):

```console
$ dig @127.0.0.1 -p 1053 +short pool.example.com
192.168.1.21
192.168.1.22
```

Edit `config.yaml` and apply it again; only what changed is written:

```bash
docker compose run --rm --no-deps configurator-configure
```

`docker compose down -v` removes the server and its data. [`examples/cluster`](../examples/cluster) does the same for a two-node cluster.

## Use it with your server

You need the server's web service URL (port `5380` by default) reachable from where the tool runs, and the admin password. Every step is safe to repeat. These examples use the Docker image; the [binary](running.md#without-docker) takes the same environment variables and arguments.

### 1. Change the default password

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="admin" \
  -e DNS_NEW_PASSWORD="new-secure-password" \
  ashtonian/technitium-configurator:3.1.0 change-password
```

```console
level=INFO msg="Password changed" user=admin
```

A re-run logs `Password is already set to the new value` and exits `0`. It tries the new password first, so re-runs do not count as failed logins.

### 2. Write a config

Start from the [quick start](../README.md#quick-start), a [recipe](recipes.md#recipes), or [an export of a server you already run](export.md#start-from-a-server-you-already-run). Put it in a directory, here `dns/config.yaml`.

### 3. Apply it

```bash
docker run --rm \
  -e DNS_API_URL="http://dns-server:5380" \
  -e DNS_USERNAME="admin" \
  -e DNS_PASSWORD="new-secure-password" \
  -v "$(pwd)/dns:/app/dns:ro" \
  ashtonian/technitium-configurator:3.1.0 configure /app/dns
```

`configure` takes files and directories; a directory means its `*.yaml` and `*.yml` files. The whole input is checked before anything changes, so a mistake stops the run with the server untouched:

```console
level=ERROR msg="Command failed" error="parse /app/dns/config.yaml: line 7: unknown record field \"ipAdress\"" command=configure
level=ERROR msg="Command failed" error="invalid config: /app/dns/config.yaml: records[1] (tv.home.arpa A).ipAddress \"192.168.1.300\" is not an IP address" command=configure
level=ERROR msg="Command failed" error="records cannot be applied; nothing was changed: /app/dns/config.yaml: records[2] (www.example.org A): no zone contains this name; declare the zone or set zone on the record" command=configure
```

Re-run it after every change to the file, from a shell, CI, a [Compose service](running.md#docker-compose) or a [Kubernetes Job](running.md#kubernetes).

For an existing server, [export its configuration](export.md) as a
starting point instead of writing everything by hand.
