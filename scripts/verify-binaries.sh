#!/usr/bin/env bash
# Checks each platform's binary in a build-binaries.sh output directory: its
# architecture, and that it runs and reports the expected version. Each one
# executes through BuildKit, so no host binfmt support is needed.
#
# Usage: scripts/verify-binaries.sh OUTPUT_DIR EXPECTED_VERSION [PLATFORM...]
# PLATFORM defaults to linux/amd64 and linux/arm64.
set -euo pipefail

usage="usage: verify-binaries.sh OUTPUT_DIR EXPECTED_VERSION [PLATFORM...]"
root=${1:?$usage}
expected=${2:?$usage}
shift 2
if (($# == 0)); then
  set -- linux/amd64 linux/arm64
fi
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cat >"$scratch/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY binary /app
RUN ["/app", "version"]
DOCKERFILE

for platform in "$@"; do
  bin="$root/$platform/technitium-configurator"
  case "$platform" in
    linux/amd64) want=x86-64 ;;
    linux/arm64) want=aarch64 ;;
    *) echo "error: no architecture check for $platform" >&2; exit 2 ;;
  esac
  file "$bin" | tee /dev/stderr | grep -q "$want"
  rm -f "$scratch/binary"
  cp "$bin" "$scratch/binary"
  if ! docker buildx build --no-cache --platform "$platform" \
    --progress plain --output type=cacheonly "$scratch" \
    >"$scratch/build.log" 2>&1; then
    cat "$scratch/build.log" >&2
    exit 1
  fi
  # Match only RUN stdout, not a Dockerfile instruction or build metadata.
  out=$(sed -nE 's/^#[0-9]+ [0-9.]+ (technitium-configurator .*)$/\1/p' "$scratch/build.log")
  echo "$platform: $out"
  if [[ $out != "technitium-configurator $expected "* ]]; then
    echo "error: $bin reports an unexpected version" >&2
    exit 1
  fi
done
