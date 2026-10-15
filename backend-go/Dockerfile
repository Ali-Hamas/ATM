# ============================================================================
# Bank-Grade Multi-Stage Dockerfile for ATM Pre-Authentication Middleware
# ============================================================================
# Stage 1: Build & Static Compilation
# ============================================================================
FROM golang:1.23-alpine AS builder

WORKDIR /src

# Install CA certificates & build tools
RUN apk add --no-cache ca-certificates git

# Cache go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Compile static binary with optimizations & symbols stripped (prevents reverse engineering)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-w -s -extldflags '-static'" \
    -o /bin/atm-auth ./cmd/server

# ============================================================================
# Stage 2: Hardened, Minimal Runtime Container
# ============================================================================
FROM alpine:3.20

# Create unprivileged bank app user & group (UID/GID 10001)
# Production banking containers must NEVER run as root (OWASP Docker Cheat Sheet)
RUN addgroup -g 10001 -S bankapp && \
    adduser -u 10001 -S bankapp -G bankapp

WORKDIR /app

# Import trusted root certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy compiled static binary
COPY --from=builder --chown=bankapp:bankapp /bin/atm-auth /app/atm-auth

# Run as unprivileged user
USER 10001:10001

# Expose internal middleware port (never directly exposed to public internet)
EXPOSE 4000

# Health check using HTTP /api/health endpoint
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1:4000/api/health || exit 1

ENTRYPOINT ["/app/atm-auth"]
