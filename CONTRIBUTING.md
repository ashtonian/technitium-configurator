# Contributing

[Documentation](docs/README.md) · [Quick start](README.md#quick-start)

- [Building, running and testing](#building-running-and-testing)
- [Code map](#code-map)

Run these commands from the repository root. See the [documentation
index](docs/README.md) for usage and configuration guides.

## Building, running and testing

```bash
go build -o technitium-configurator .
./technitium-configurator version

docker build -t technitium-configurator .
docker buildx build --platform linux/amd64,linux/arm64 -t technitium-configurator .

go test -race ./...                  # unit tests, including DNS configs in the README, docs/ and examples/
go test -tags e2e ./e2e              # needs Docker; starts Technitium 15.6.1 containers
```

The unit tests load every `yaml` block in `README.md`, `docs/*.md` and `.github/DOCKERHUB.md`, and every DNS config under `examples/`, through the same loader and validation `configure` uses. A YAML block that is not a DNS config is marked with `<!-- docs-test: not a DNS config -->` on the line before it.

The e2e suite checks the values a fresh install ends up with; that an unchanged re-run writes nothing but settings and zone options; record policies and values the server stores in another form; PTR preservation; IDN names; ACL clearing; administration; export applied back to its server and restored onto a fresh one; a re-run authenticated with the token file `create-token` wrote; the binary's exit codes and output streams; and a two-node cluster in which zones replicate, a local zone stays local, and the secondary re-runs with its original credentials and with a token it no longer has.

GitHub Actions runs vet, lint, the unit tests, govulncheck and the e2e suite on every pull request and push. Only when they pass does it build both platforms' binaries, check each one's architecture and that it reports the version (for a release, the tag without its `v`), and then build and push the images from the same inputs. Pushes to `main` publish `beta` and `beta-<date>-<sha>`. A `v*` tag publishes `<version>` (and `v<version>` for versions without a prerelease suffix), moves `latest` only for those, marks tags with a suffix as prereleases, and creates a GitHub release from that version's section of `RELEASE_NOTES.md`.

## Code map

| Path | Contents |
|---|---|
| `main.go` | CLI entry: client configuration precedence, logging, signal handling, exit codes, `version` output |
| `cmd/cli.go` | Command-line parsing: commands, flags, arguments, usage text |
| `cmd/commands.go` | Commands: `configure` entry, `create-token`, `change-password`, `export`, `cluster-state`; authentication |
| `cmd/version.go` | What `version` prints: `-ldflags` values, completed from the module version and commit Go records in the binary |
| `cmd/configure.go` | One configure pass: checks before any change, then settings, cluster, administration, zones, FWD records, apps, other records |
| `pkg/technitium/client.go`, `errors.go`, `logging.go` | HTTP client, response envelope, typed errors, request logging |
| `pkg/technitium/config.go`, `validate.go` | DNS config schema, multi-file loading and merging, validation |
| `pkg/technitium/plan.go` | Decisions without I/O: catalogs, ACL overrides, record placement and plans, TSIG merging |
| `pkg/technitium/rdata.go`, `names.go`, `rrtypes.go` | Record value comparison and conversion; canonical DNS names and zone keys; the server's record type table |
| `pkg/technitium/dns_settings.go`, `zone.go`, `records.go`, `apps.go`, `cluster.go`, `admin.go` | API calls and types per area |
| `pkg/technitium/export.go` | `export`: reading a server back into the schema |
| `pkg/technitium/client_config.go`, `token_file.go` | Client configuration and its validation; reading the API token file |
| `pkg/technitium/docs_test.go` | Loads every DNS config in the README, the guides, the Docker Hub overview and `examples/` |
| `pkg/kube` | Kubernetes Secret storage for `create-token`, and the current namespace |
| `e2e/` | End-to-end tests against Technitium containers, and the built binary's exit codes |
| `examples/config.yaml` | Full DNS config reference |
| `examples/docker-compose.yaml` | One server, configured by Compose |
| `examples/cluster/` | Two-node cluster with Compose: `compose.yaml`, `primary.yaml`, `secondary.yaml` |
| `examples/k8s.yaml` | Kubernetes Job, RBAC and credentials |
| `.github/workflows/` | CI: test, e2e, image build and release (`docker.yml`); Docker Hub overview publishing (`dockerhub-description.yml`) |
| `.github/DOCKERHUB.md` | The Docker Hub overview; changes are published when they reach `main` |
