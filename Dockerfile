# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

# The build context holds binaries cross-compiled on the build host, one per
# platform at <os>/<arch>/technitium-configurator (scripts/build-binaries.sh),
# so no platform compiles or runs anything here.

# Only the CA bundle comes from here; it is the same for every platform.
FROM --platform=$BUILDPLATFORM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931 AS certs

FROM scratch
ARG TARGETPLATFORM
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="technitium-configurator" \
      org.opencontainers.image.source="https://github.com/ashtonian/technitium-configurator" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}"
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chmod=0555 $TARGETPLATFORM/technitium-configurator /technitium-configurator
USER 65532:65532
# Relative paths such as the default config.yaml resolve here.
WORKDIR /app
ENTRYPOINT ["/technitium-configurator"]
