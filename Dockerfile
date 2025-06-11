# syntax=docker/dockerfile:1.4

# Build stage
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

WORKDIR /app

# Install git and build dependencies
RUN apk add --no-cache git

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o technitium-configurator

# Final stage
FROM --platform=$TARGETPLATFORM alpine:latest

WORKDIR /app

# Copy the binary
COPY --from=builder /app/technitium-configurator /app/

ENTRYPOINT ["/app/technitium-configurator"]