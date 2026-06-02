# Build Stage
# Using Chainguard's Go image for a secure, hardened build environment
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with optimizations and static linking
# CGO is disabled for the static runtime
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o secretd \
    ./cmd/secretd/main.go

# Production Stage
# Using Chainguard's static image for maximum security and minimal size
FROM cgr.dev/chainguard/static:latest

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/secretd .

# Default configuration environment variables
ENV SECRETD_LISTEN=0.0.0.0:8090
ENV SECRETD_DB_PATH=/data/secretd.db

# Expose the service port
EXPOSE 8090

# Command to run the service
# Note: SECRETD_ADMIN_TOKEN and SECRETD_MASTER_KEY should be provided at runtime
ENTRYPOINT ["./secretd"]
