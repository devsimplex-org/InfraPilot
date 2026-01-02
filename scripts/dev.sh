#!/bin/bash
set -e

# InfraPilot Development Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Use docker compose (v2) or docker-compose (v1)
if docker compose version &> /dev/null; then
  COMPOSE="docker compose"
else
  COMPOSE="docker-compose"
fi

case "$1" in
  "up")
    echo "Starting development environment..."
    cd "$PROJECT_ROOT/deployments"
    $COMPOSE up -d postgres redis
    echo "Waiting for services..."
    sleep 3
    echo "Database and Redis are ready!"
    echo ""
    echo "To start the backend: cd backend && go run ./cmd/server"
    echo "To start the frontend: cd frontend && npm run dev"
    ;;

  "down")
    echo "Stopping development environment..."
    cd "$PROJECT_ROOT/deployments"
    $COMPOSE down
    ;;

  "reset")
    echo "Resetting database..."
    cd "$PROJECT_ROOT/deployments"
    $COMPOSE down -v
    $COMPOSE up -d postgres redis
    echo "Database reset complete!"
    ;;

  "logs")
    cd "$PROJECT_ROOT/deployments"
    $COMPOSE logs -f "${@:2}"
    ;;

  "proto")
    echo "Generating protobuf code..."
    cd "$PROJECT_ROOT"
    protoc --go_out=backend --go-grpc_out=backend \
           --go_opt=paths=source_relative \
           --go-grpc_opt=paths=source_relative \
           proto/agent/v1/agent.proto
    echo "Protobuf generation complete!"
    ;;

  "migrate")
    echo "Running migrations..."
    cd "$PROJECT_ROOT/deployments"
    $COMPOSE exec postgres psql -U infrapilot -d infrapilot -f /docker-entrypoint-initdb.d/001_initial_schema.sql
    ;;

  "seed")
    echo "Seeding database..."
    cd "$PROJECT_ROOT"
    $COMPOSE -f deployments/docker-compose.yml exec -T postgres psql -U infrapilot -d infrapilot < scripts/seed.sql
    echo ""
    echo "Test users created:"
    echo "  admin@infrapilot.local / admin123 (super_admin)"
    echo "  operator@infrapilot.local / admin123 (operator)"
    echo "  viewer@infrapilot.local / admin123 (viewer)"
    ;;

  "air")
    echo "Installing Air for hot reload..."
    go install github.com/air-verse/air@latest
    echo "Air installed! Run 'cd backend && air' to start with hot reload"
    ;;

  *)
    echo "InfraPilot Development Commands"
    echo ""
    echo "Usage: ./scripts/dev.sh <command>"
    echo ""
    echo "Commands:"
    echo "  up      Start development services (postgres, redis)"
    echo "  down    Stop development services"
    echo "  reset   Reset database (destroys all data)"
    echo "  logs    View service logs"
    echo "  proto   Generate protobuf code"
    echo "  migrate Run database migrations"
    echo "  seed    Create test users and data"
    echo "  air     Install Air for hot reload"
    echo ""
    echo "Quick Start:"
    echo "  1. ./scripts/dev.sh up"
    echo "  2. cd backend && go run ./cmd/server"
    echo "  3. cd frontend && npm run dev"
    ;;
esac
