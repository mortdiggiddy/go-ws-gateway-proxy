# ─── Builder Stage ───────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

# Disable CGO, enable Go modules
ENV CGO_ENABLED=0 \
    GO111MODULE=on

WORKDIR /app

# Fetch dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source, then compile with optimizations
COPY . .
RUN go build -ldflags="-s -w" -o gateway ./cmd/main.go

# ─── Runtime Stage ───────────────────────────────────────────────────────────────
FROM alpine:3.18

# Install wget (for HEALTHCHECK) and ca-certificates
RUN apk add --no-cache wget ca-certificates

# Create a dedicated non‑root user and group with fixed UID/GID
# RUN addgroup -g 1001 -S appgroup \
#  && adduser  -u 1001 -S appuser  -G appgroup \
#  && mkdir /app \
#  && chown appuser:appgroup /app

# Create app directory owned by root, group-writable (OpenShift‐compliant)
RUN mkdir /app \
 && chown root:root /app \
 && chmod g=u /app

WORKDIR /app

COPY --from=builder /app/gateway .

# RUN chown appuser:appgroup /app/gateway
# USER appuser:appgroup

# no USER line at all—let OpenShift pick a random UID
EXPOSE 8080

# Healthcheck for Kubernetes liveness/readiness probes
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Metadata
LABEL org.opencontainers.image.source="https://github.com/mortdiggiddy/go-ws-gateway-proxy" \
      org.opencontainers.image.maintainer="Your Name <you@example.com>"

ENTRYPOINT ["./gateway"]
