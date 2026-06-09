# Build Stage
# Using Chainguard's Go image for a secure, hardened build environment
FROM cgr.dev/chainguard/go:latest AS builder

# Build arguments provided by Docker Buildx for multi-arch builds
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Run prebuild to generate CLI binaries and web assets
RUN go run cmd/prebuild/main.go
RUN sed -i 's/SCRIPT_SOURCE="github"/SCRIPT_SOURCE="docker"/' public/install.sh

# Create empty directories for volumes so we can copy them with correct permissions
RUN mkdir -p /app/data /app/backups

ARG APP_VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -X main.Version=${APP_VERSION}" \
    -o tiny-secrets-manager \
    ./cmd/tsm-server/main.go

# Production Stage
# Using Chainguard's static image for maximum security and minimal size
FROM cgr.dev/chainguard/static:latest

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/tiny-secrets-manager .
# Copy CLI binaries from builder
COPY --from=builder /app/bin/cli /app/cli

# Create mount points with correct nonroot ownership
COPY --chown=nonroot:nonroot --from=builder /app/data /data
COPY --chown=nonroot:nonroot --from=builder /app/backups /backups

# Default configuration environment variables
ENV TSM_LISTEN=0.0.0.0:8090
ENV TSM_DB_PATH=/data/tsm.db
ENV TSM_CLI_DIR=/app/cli

# Expose the service port
EXPOSE 8090

# Command to run the service
# Note: TSM_ADMIN_TOKEN and TSM_MASTER_KEY should be provided at runtime
ENTRYPOINT ["./tiny-secrets-manager"]
