# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build binary with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION:-dev}" \
    -a -installsuffix cgo \
    -o server ./cmd/server

# Runtime stage - using distroless for security
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy CA certificates
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary from builder
COPY --from=builder /app/server .

# Copy migrations for init
COPY --from=builder /app/internal/db/migrations ./migrations

# Use non-root user (provided by distroless:nonroot)
USER nonroot:nonroot

EXPOSE 8080 9090

ENTRYPOINT ["./server"]
