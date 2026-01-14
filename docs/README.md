# InfraPilot Documentation

Welcome to the InfraPilot documentation! This guide will help you understand, deploy, and extend InfraPilot.

## What is InfraPilot?

InfraPilot is a Docker-native infrastructure control plane that provides a unified web-based dashboard for managing traffic, containers, logs, security, and alerts without requiring SSH access to the host OS.

## Documentation Structure

### Getting Started
- [Main README](../README.md) - Quick start and overview
- [Deployment Guide](DEPLOYMENT.md) - Production deployment instructions
- [Configuration Reference](CONFIGURATION.md) - Environment variables and settings

### Technical Documentation
- [Architecture Overview](ARCHITECTURE.md) - System design and component interactions
- [API Reference](API-REFERENCE.md) - REST API endpoints and usage
- [Development Guide](DEVELOPMENT.md) - Local development setup and workflow

### DevSecOps
- [DevSecOps Roadmap](DEVSECOPS-ROADMAP.md) - Transformation plan and timeline
- [DevSecOps Epics](DEVSECOPS-EPICS.md) - Detailed implementation instructions

### Operations
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Common issues and solutions

## Quick Links

### For Users
- **First Time Setup**: See [main README](../README.md#quick-start)
- **Production Deployment**: See [Deployment Guide](DEPLOYMENT.md)
- **Configuration Options**: See [Configuration Reference](CONFIGURATION.md)
- **Common Issues**: See [Troubleshooting Guide](TROUBLESHOOTING.md)

### For Developers
- **Architecture Overview**: See [Architecture](ARCHITECTURE.md)
- **Development Setup**: See [Development Guide](DEVELOPMENT.md)
- **API Documentation**: See [API Reference](API-REFERENCE.md)

### For DevSecOps
- **Transformation Roadmap**: See [DevSecOps Roadmap](DEVSECOPS-ROADMAP.md)
- **Implementation Epics**: See [DevSecOps Epics](DEVSECOPS-EPICS.md)

## Key Features

### Reverse Proxy Management
- Visual Nginx configuration with live preview
- Automatic SSL certificates (Let's Encrypt)
- Security headers (HSTS, CSP, X-Frame-Options)
- Rate limiting and IP allow/deny lists
- Dynamic Docker network attachment

### Container Operations
- Container list with real-time metrics
- Start, stop, restart controls
- Live log streaming
- Web-based terminal (container exec)
- Docker Compose stack grouping

### Observability
- Unified log aggregation
- Real-time log streaming with search
- Nginx access and error logs
- Container log collection

### Alerting
- Multiple channels: SMTP, Slack, Webhooks
- Container crash detection
- SSL expiry warnings
- High error rate alerts

### Security
- Role-based access control (RBAC)
- Multi-factor authentication (TOTP)
- Complete audit trail
- TLS health scoring

### DevSecOps (Roadmap)
- Supply chain security (image scanning, SBOM)
- Policy-as-code (OPA integration)
- Runtime drift detection
- CI/CD integration
- Security posture dashboard

## System Requirements

- Docker 24+
- 2 CPU cores minimum (4 recommended)
- 4 GB RAM minimum
- Linux x86_64 / ARM64

## Support

- **Documentation**: You're reading it!
- **Security Issues**: security@infrapilot.org
- **Enterprise Support**: enterprise@infrapilot.org

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

## License

Apache License 2.0 - see [LICENSE](../LICENSE)
