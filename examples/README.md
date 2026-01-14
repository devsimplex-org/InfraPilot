# Examples

This folder contains example configurations for InfraPilot deployments.

## Files

### `docker-compose.infrapilot.yml`

**Recommended** - Production deployment with the all-in-one InfraPilot image.

```bash
# Generate a secure JWT secret
openssl rand -base64 32

# Create .env file with your secret
echo "JWT_SECRET=your-generated-secret" > .env

# Start InfraPilot
docker compose -f docker-compose.infrapilot.yml up -d

# Access at http://your-server-ip
```

### `docker-compose.sample-app.yml`

A sample web application for testing proxy configurations.

```bash
# Start sample app
docker compose -f docker-compose.sample-app.yml up -d

# Add to /etc/hosts
echo "127.0.0.1 sample.local" | sudo tee -a /etc/hosts

# Create proxy in InfraPilot pointing to sample-app:80
```

### `docker-compose.external-proxy.yml`

Examples for using InfraPilot with external reverse proxies:

- NGINX Proxy Manager
- Traefik
- Caddy
- HAProxy

Use this when you want to manage your own proxy instead of using InfraPilot's bundled Nginx.

```bash
# Set external proxy mode
export PROXY_MODE=external

# Start InfraPilot without managed Nginx
docker compose up -d

# Configure your external proxy separately
```
