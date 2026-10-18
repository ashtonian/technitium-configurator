#!/usr/bin/env bash
# Execute each exported binary through BuildKit without host binfmt support.
set -euo pipefail

root=${1:?usage: verify-binaries.sh OUTPUT_DIR EXPECTED_VERSION}
expected=${2:?usage: verify-binaries.sh OUTPUT_DIR EXPECTED_VERSION}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cat >"$scratch/Dockerfile" <<'DOCKERFILE'
FROM scratch
COPY binary /app
RUN ["/app", "version"]
DOCKERFILE

for arch in amd64 arm64; do
  bin="$root/linux_$arch/technitium-configurator"
  case "$arch" in
    amd64) want=x86-64 ;;
    arm64) want=aarch64 ;;
  esac
  file "$bin" | tee /dev/stderr | grep -q "$want"
  rm -f "$scratch/binary"
  cp "$bin" "$scratch/binary"
  if ! docker buildx build --no-cache --platform "linux/$arch" \
    --progress plain --output type=cacheonly "$scratch" \
    >"$scratch/build.log" 2>&1; then
    cat "$scratch/build.log" >&2
    exit 1
  fi
  # Match only RUN stdout, not a Dockerfile instruction or build metadata.
  out=$(sed -nE 's/^#[0-9]+ [0-9.]+ (technitium-configurator .*)$/\1/p' "$scratch/build.log")
  echo "linux/$arch: $out"
  if [[ $out != "technitium-configurator $expected "* ]]; then
    echo "error: $bin reports an unexpected version" >&2
    exit 1
  fi
done
