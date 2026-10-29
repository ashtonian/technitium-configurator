# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

ARG GO_IMAGE=golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9

# Cross-compiles on the build platform for each target platform.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
# Automatic platform args are global; a stage must redeclare them to use them.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY main.go ./
COPY cmd ./cmd
COPY pkg ./pkg
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -n "$TARGETOS" && test -n "$TARGETARCH" && \
    GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid= -X main.version=${VERSION:-dev} -X main.commit=${REVISION:-unknown} -X main.buildDate=${BUILD_DATE:-unknown}" \
      -o /out/technitium-configurator . && \
    find /root/.cache/go-build -type f -mmin +120 -delete

FROM scratch
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="technitium-configurator" \
      org.opencontainers.image.source="https://github.com/ashtonian/technitium-configurator" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${BUILD_DATE}"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chmod=0555 /out/technitium-configurator /technitium-configurator
USER 65532:65532
# Relative paths such as the default config.yaml resolve here.
WORKDIR /app
ENTRYPOINT ["/technitium-configurator"]
