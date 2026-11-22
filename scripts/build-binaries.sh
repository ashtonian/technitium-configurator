#!/usr/bin/env bash
# Cross-compiles technitium-configurator on the build host into
# OUT_DIR/<os>/<arch>/technitium-configurator, the per-platform layout the
# Dockerfile copies from, so an image build compiles nothing and runs
# nothing under emulation.
#
# Usage: scripts/build-binaries.sh OUT_DIR VERSION REVISION BUILD_DATE PLATFORM...
#   scripts/build-binaries.sh build/image dev "$(git rev-parse HEAD)" unknown linux/amd64
#   docker buildx build --platform linux/amd64 -f Dockerfile -t technitium-configurator build/image
set -euo pipefail

usage="usage: build-binaries.sh OUT_DIR VERSION REVISION BUILD_DATE PLATFORM..."
out=${1:?$usage}
version=${2:?$usage}
revision=${3:?$usage}
build_date=${4:?$usage}
shift 4
if (($# == 0)); then
  echo "$usage" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
for platform in "$@"; do
  if [[ ! $platform =~ ^[a-z0-9]+/[a-z0-9]+$ ]]; then
    echo "error: platform must be os/arch, got '$platform'" >&2
    exit 2
  fi
  CGO_ENABLED=0 GOOS=${platform%/*} GOARCH=${platform#*/} \
    go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags="-s -w -buildid= -X main.version=$version -X main.commit=$revision -X main.buildDate=$build_date" \
    -o "$out/$platform/technitium-configurator" .
done
