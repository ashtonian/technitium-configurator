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

# The image packages binaries cross-compiled on the host, one per platform
# at build/image/<os>/<arch>/technitium-configurator.
scripts/build-binaries.sh build/image dev "$(git rev-parse HEAD)" unknown linux/amd64 linux/arm64
scripts/verify-binaries.sh build/image dev
docker buildx build --platform linux/amd64,linux/arm64 -f Dockerfile -t technitium-configurator build/image

go test -race ./...                  # unit tests, including DNS configs in the README, docs/ and examples/
go test -tags e2e ./e2e              # needs Docker; defaults to Technitium 15.6.2 containers
```

The unit tests load every `yaml` block in `README.md`, `docs/*.md` and `.github/DOCKERHUB.md`, and every DNS config under `examples/`, through the same loader and validation `configure` uses. A YAML block that is not a DNS config is marked with `<!-- docs-test: not a DNS config -->` on the line before it.

The e2e suite checks the values a fresh install ends up with; that an unchanged re-run writes nothing but settings and zone options; record policies and values the server stores in another form; PTR preservation; IDN names; ACL clearing; administration; export applied back to its server and restored onto a fresh one; a re-run authenticated with the token file `create-token` wrote; the binary's exit codes and output streams; and a two-node cluster in which zones replicate, a local zone stays local, and the secondary re-runs with its original credentials and with a token it no longer has.

GitHub Actions (`docker.yml`) runs vet, lint, the unit tests and govulncheck (`test`), the e2e suite (`e2e`), and the image build (`build-and-push`), but only the jobs a change needs. A `scope` job ([go-ci-actions scope](https://github.com/ashtonian/go-ci-actions#change-scope)) works out the affected packages: the changed ones plus every package that imports one, with the `e2e` tag. `test` checks only those. `e2e` and `build-and-push` run when the binary (the root package) is affected or, for `e2e`, the e2e package; `build-and-push` also runs when `Dockerfile` or its scripts change. The docs test reads `README.md`, `.github/DOCKERHUB.md`, `docs/*.md` and the example configs, so a change to one of those counts as a change to `pkg/technitium` (`go-owners` in the scope step). Add a file there when a test starts reading it from outside its own directory. A pull request is measured from its base, a push to `main` from the last green run there. A change to `docker.yml`, `go.mod` or `go.sum`, a file no package owns, a tag, the nightly schedule (skipped when `main` has not moved since the last green one), a manual run and the `full-ci` label run everything.

The binaries are cross-compiled on the runner, and each is checked for its architecture and for reporting the version (for a release, the tag without its `v`). The image is then built from those same binaries. A pull request and the nightly build linux/amd64 only, push nothing and add no attestations; `main` and tags build both platforms and push them with provenance and an SBOM.

A pull request's run ends by recording a receipt of the tested merge tree and the jobs that passed ([go-ci-actions acceptance](https://github.com/ashtonian/go-ci-actions#push-acceptance)). The push to `main` that merges it skips every check its own scope selects that passed on the same tree, when the commit its scope is measured from (the last green run on `main`) is green, and builds and pushes the beta image when the image's inputs changed. A squash or rebase merge, a direct push, a re-run or a pull request run older than six hours runs its scoped checks. Pushes to `main` publish `beta` and `beta-<date>-<sha>`. A `v*` tag publishes `<version>` (and `v<version>` for versions without a prerelease suffix), moves `latest` only for those, marks tags with a suffix as prereleases, and creates a GitHub release from that version's section of `RELEASE_NOTES.md`.

## Code map

CI runs the standalone and cluster suites on pinned Technitium 15.6.1 and
15.6.2 images; `DNS_SERVER_IMAGE` selects the image locally. The cluster suite
runs both literal and discovered-address configurations. Its
discovery case replaces a member's advertised address with an incorrect one,
observes the native catalog ACL, restores the discovered address and checks
subsequent record replication. A real UDP NOTIFY regression verifies refusal
of an unrecognized sender, acceptance through an explicit trusted-network
policy and refusal again after that policy is cleared. The single-node suite also exercises first-boot
password setup, mounted-config reload, recovery from invalid configuration and
signal-driven reconciliation shutdown. A cold-start app test uses the canonical
Advanced Blocking example, a persistent server volume and real UDP/TCP query
results, checking both the app's blocking report and an allowed persisted record. Unit coverage uses an injected wait
and virtual time for retry/deadline behavior.

| Path | Contents |
|---|---|
| `main.go` | CLI entry: client configuration precedence, logging, signal handling, exit codes, `version` output |
| `cmd/cli.go` | Command-line parsing: commands, flags, arguments, usage text |
| `cmd/commands.go` | Commands: `configure` entry, `create-token`, `change-password`, `export`, `cluster-state`; authentication |
| `cmd/version.go` | What `version` prints: `-ldflags` values, completed from the module version and commit Go records in the binary |
| `cmd/configure.go` | One configure pass: checks before any change, then settings, cluster, administration, zones, FWD records, apps, other records |
| `cmd/reconcile.go` | Bounded passes using configure, mounted configuration/token reload, retries and cancellation |
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
| `Dockerfile` | The image: a platform's pre-built binary and a CA bundle on `scratch` |
| `scripts/build-binaries.sh` | Cross-compiles the image's binaries into the per-platform layout the `Dockerfile` copies from |
| `scripts/verify-binaries.sh` | Checks each binary's architecture and reported version by running it through BuildKit |
| `.github/workflows/` | CI: test, e2e, image build and release (`docker.yml`); Docker Hub overview publishing (`dockerhub-description.yml`) |
| `.github/DOCKERHUB.md` | The Docker Hub overview; changes are published when they reach `main` |
