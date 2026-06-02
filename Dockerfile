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

# Build the binary with optimizations and static linking
# CGO is disabled for the static runtime
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w" \
    -o tiny-secrets-manager \
    ./cmd/tsm-server/main.go

# Production Stage
# Using Chainguard's static image for maximum security and minimal size
FROM cgr.dev/chainguard/static:latest

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/tiny-secrets-manager .

# Default configuration environment variables
ENV TSM_LISTEN=0.0.0.0:8090
ENV TSM_DB_PATH=/data/tsm.db

# Expose the service port
EXPOSE 8090

# Command to run the service
# Note: TSM_ADMIN_TOKEN and TSM_MASTER_KEY should be provided at runtime
ENTRYPOINT ["./tiny-secrets-manager"]
