# syntax=docker/dockerfile:1.4

# Build stage
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

WORKDIR /app

# Install git and build dependencies
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Copy source code
COPY . .

# Build the application
ARG GO_BUILD_FLAGS="-ldflags=-s -w"
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build ${GO_BUILD_FLAGS} -o technitium-configurator

# Final stage
FROM --platform=$TARGETPLATFORM alpine:latest

WORKDIR /app

# Copy the binary and config
COPY --from=builder /app/technitium-configurator /app/
COPY --from=builder /app/config.yaml /app/

ENTRYPOINT ["/app/technitium-configurator"]