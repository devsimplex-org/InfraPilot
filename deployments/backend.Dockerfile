# =============================================================
# InfraPilot Backend - API Server
# =============================================================

FROM golang:1.24-alpine AS builder

WORKDIR /build

RUN apk add --no-cache git ca-certificates tzdata

# Copy go modules
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -a -installsuffix cgo \
    -o /backend ./cmd/server

# -------------------------------------------------------------
# Runtime Stage
# -------------------------------------------------------------
FROM alpine:3.21

# OCI Labels
LABEL org.opencontainers.image.title="InfraPilot Backend"
LABEL org.opencontainers.image.description="InfraPilot API Server"
LABEL org.opencontainers.image.source="https://github.com/devsimplex-org/infrapilot"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="DevSimplex"

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    bash \
    wget \
    && rm -rf /var/cache/apk/*

# Install Trivy for vulnerability scanning with retry logic
RUN wget -q -O /tmp/install-trivy.sh https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh && \
    chmod +x /tmp/install-trivy.sh && \
    (/tmp/install-trivy.sh -b /usr/local/bin || (sleep 5 && /tmp/install-trivy.sh -b /usr/local/bin)) && \
    rm /tmp/install-trivy.sh && \
    trivy --version

# Install Syft for SBOM generation with retry logic
RUN wget -q -O /tmp/install-syft.sh https://raw.githubusercontent.com/anchore/syft/main/install.sh && \
    chmod +x /tmp/install-syft.sh && \
    (/tmp/install-syft.sh -b /usr/local/bin || (sleep 5 && /tmp/install-syft.sh -b /usr/local/bin)) && \
    rm /tmp/install-syft.sh && \
    syft version

# Install OPA (Open Policy Agent) for policy evaluation
RUN wget -q -O /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static && \
    chmod +x /usr/local/bin/opa && \
    opa version

# Create app user
RUN adduser -D -H -s /sbin/nologin appuser

WORKDIR /app

# Copy binary and migrations
COPY --from=builder /backend /app/server
COPY internal/db/migrations /app/migrations

# Set ownership
RUN chown -R appuser:appuser /app

USER appuser

# Environment
ENV ENV=production
ENV HTTP_PORT=8080
ENV GRPC_PORT=9090

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["/app/server"]
