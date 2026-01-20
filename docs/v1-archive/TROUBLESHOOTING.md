# Troubleshooting Guide

Common issues and solutions for InfraPilot deployments.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Container Issues](#container-issues)
- [Database Issues](#database-issues)
- [SSL/TLS Issues](#ssltls-issues)
- [Proxy Issues](#proxy-issues)
- [Agent Issues](#agent-issues)
- [Authentication Issues](#authentication-issues)
- [Performance Issues](#performance-issues)
- [Network Issues](#network-issues)
- [Logging Issues](#logging-issues)
- [Upgrade Issues](#upgrade-issues)
- [Data Issues](#data-issues)

## Installation Issues

### Container Won't Start

**Symptom**: InfraPilot container exits immediately

**Check logs**:
```bash
docker logs infrapilot
```

**Common causes**:

1. **Missing JWT_SECRET**
   ```
   Error: JWT_SECRET environment variable is required
   ```
   **Solution**:
   ```bash
   export JWT_SECRET=$(openssl rand -base64 32)
   docker compose up -d
   ```

2. **Port already in use**
   ```
   Error: bind: address already in use
   ```
   **Solution**:
   ```bash
   # Find process using port 80
   sudo lsof -i :80

   # Either stop the conflicting service or change port
   # Option 1: Stop conflicting service
   sudo systemctl stop apache2

   # Option 2: Use different port
   docker run -p 8080:80 ...
   ```

3. **Docker socket permission denied**
   ```
   Error: permission denied while trying to connect to Docker daemon
   ```
   **Solution**:
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER

   # Logout and login again, or:
   newgrp docker
   ```

---

### Database Migration Failed

**Symptom**: Container starts but database migrations fail

**Check logs**:
```bash
docker logs infrapilot | grep -i migration
```

**Solution**:
```bash
# Stop container
docker compose stop infrapilot

# Remove database (WARNING: loses data)
docker volume rm infrapilot_data

# Or backup and restore
docker run --rm -v infrapilot_data:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz /data

# Restart
docker compose up -d
```

---

## Container Issues

### Cannot Start Containers

**Symptom**: Container operations fail with timeout

**Check**:
```bash
# Verify Docker is running
docker ps

# Check Docker socket mount
docker inspect infrapilot | grep -A 5 Mounts
```

**Solution**:
```bash
# Ensure Docker socket is mounted
docker run -v /var/run/docker.sock:/var/run/docker.sock:ro ...

# Check Docker socket permissions
ls -la /var/run/docker.sock
sudo chmod 666 /var/run/docker.sock  # Not recommended for production
```

---

### Container Exec Not Working

**Symptom**: Web terminal won't connect or shows errors

**Check browser console**: Look for WebSocket errors

**Common causes**:

1. **WebSocket not supported by reverse proxy**

   **Solution for Nginx**:
   ```nginx
   location /api/v1/agents/ {
       proxy_pass http://backend;
       proxy_http_version 1.1;
       proxy_set_header Upgrade $http_upgrade;
       proxy_set_header Connection "upgrade";
   }
   ```

2. **Firewall blocking WebSocket**

   **Solution**:
   ```bash
   # Allow WebSocket traffic
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   ```

---

### Container Metrics Not Updating

**Symptom**: CPU/Memory metrics show 0% or don't update

**Check**:
```bash
# Verify agent is collecting metrics
docker logs infrapilot | grep -i metrics

# Check database connection
docker exec infrapilot psql -U infrapilot -c "SELECT COUNT(*) FROM container_metrics"
```

**Solution**:
```bash
# Restart container
docker compose restart infrapilot

# If persists, check agent configuration
docker exec infrapilot cat /etc/infrapilot/agent.conf
```

---

## Database Issues

### Database Connection Failed

**Symptom**: `Failed to connect to database` error

**For embedded database**:
```bash
# Check if PostgreSQL is running
docker exec infrapilot ps aux | grep postgres

# Check disk space
docker exec infrapilot df -h

# Check logs
docker logs infrapilot | grep -i postgres
```

**For external database**:
```bash
# Test connection
psql -h db-host -U infrapilot -d infrapilot

# Check DATABASE_URL format
echo $DATABASE_URL
# Should be: postgres://user:pass@host:port/db
```

**Solution**:
```bash
# Correct DATABASE_URL
export DATABASE_URL="postgres://infrapilot:password@db.example.com:5432/infrapilot?sslmode=require"

# Restart container
docker compose restart infrapilot
```

---

### Database Out of Disk Space

**Symptom**: Database writes fail, container becomes unresponsive

**Check**:
```bash
# Check volume usage
docker system df -v

# Check database size
docker exec infrapilot du -sh /data/postgres
```

**Solution**:
```bash
# Clean up old logs
docker exec infrapilot psql -U infrapilot -c "DELETE FROM logs WHERE created_at < NOW() - INTERVAL '30 days'"

# Vacuum database
docker exec infrapilot psql -U infrapilot -c "VACUUM FULL"

# Or increase volume size (depends on storage backend)
```

---

### Connection Pool Exhausted

**Symptom**: `sorry, too many clients already` error

**Check**:
```bash
# Check active connections
docker exec infrapilot psql -U infrapilot -c "SELECT count(*) FROM pg_stat_activity"
```

**Solution**:
```bash
# Increase max_connections in PostgreSQL
# For external database, edit postgresql.conf:
max_connections = 200

# For embedded, increase pool size via DATABASE_URL:
DATABASE_URL="postgres://...?pool_max_conns=50"

# Restart
docker compose restart infrapilot
```

---

## SSL/TLS Issues

### SSL Certificate Request Failed

**Symptom**: `Failed to obtain certificate` error

**Check**:
```bash
# Check agent logs
docker logs infrapilot | grep -i ssl

# Verify domain points to server
dig +short yourdomain.com
# Should return your server's IP

# Test port 80 is accessible
curl -I http://yourdomain.com
```

**Common causes**:

1. **DNS not pointing to server**

   **Solution**: Update DNS A record to point to server IP

2. **Port 80 blocked by firewall**

   **Solution**:
   ```bash
   sudo ufw allow 80/tcp
   sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
   ```

3. **Let's Encrypt rate limit exceeded**

   **Solution**: Use staging environment
   ```bash
   LETSENCRYPT_STAGING=true
   ```

4. **ACME challenge validation failed**

   **Check**: Ensure `.well-known/acme-challenge/` is accessible
   ```bash
   curl http://yourdomain.com/.well-known/acme-challenge/test
   ```

---

### Wildcard Certificate Failed

**Symptom**: DNS-01 challenge fails

**Check**:
```bash
# Verify TXT record
dig +short _acme-challenge.yourdomain.com TXT

# Should show challenge value provided by InfraPilot
```

**Solution**:
```bash
# Wait 5-10 minutes for DNS propagation
# Then retry challenge

# Use online DNS checker
# https://dnschecker.org

# If still failing, check DNS provider API credentials
```

---

### Certificate Not Auto-Renewing

**Symptom**: Certificate expires

**Check**:
```bash
# Check certificate expiry
echo | openssl s_client -servername yourdomain.com -connect yourdomain.com:443 2>/dev/null | openssl x509 -noout -dates

# Check renewal cron job
docker exec infrapilot crontab -l
```

**Solution**:
```bash
# Manual renewal
docker exec infrapilot /usr/local/bin/renew-certificates.sh

# Check logs for renewal errors
docker logs infrapilot | grep -i renew
```

---

### SSL Handshake Failed

**Symptom**: `SSL handshake failed` in browser

**Check**:
```bash
# Test SSL configuration
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com

# Check certificate chain
curl -vI https://yourdomain.com
```

**Solution**:
```bash
# Ensure full certificate chain is used
# Certificate should include intermediate certificates

# Verify certificate paths in proxy configuration
docker exec infrapilot cat /etc/nginx/sites-enabled/yourdomain.com.conf
```

---

## Proxy Issues

### 502 Bad Gateway

**Symptom**: Proxy host shows 502 error

**Check**:
```bash
# Check if upstream container is running
docker ps | grep container-name

# Check if upstream port is accessible
docker exec infrapilot curl http://container-name:8080

# Check Nginx logs
docker logs infrapilot | grep -i nginx
```

**Common causes**:

1. **Upstream container not running**

   **Solution**: Start the container
   ```bash
   docker start container-name
   ```

2. **Wrong port**

   **Solution**: Update proxy host configuration with correct port

3. **Container not on same network**

   **Solution**: Attach Nginx to container's network
   - Go to Networks tab
   - Attach InfraPilot to container's network

4. **Container firewall blocking**

   **Solution**: Check container's internal firewall/security groups

---

### 504 Gateway Timeout

**Symptom**: Requests timeout after 60 seconds

**Solution**:
```bash
# Increase proxy timeout in Nginx configuration
# Add custom configuration:
proxy_read_timeout 300s;
proxy_connect_timeout 300s;
proxy_send_timeout 300s;
```

**In InfraPilot UI**:
- Edit proxy host
- Advanced → Custom Nginx Configuration
- Add timeout directives

---

### Nginx Configuration Test Failed

**Symptom**: `nginx -t` fails when testing configuration

**Check**:
```bash
# View Nginx error
docker exec infrapilot nginx -t
```

**Common errors**:

1. **Duplicate server_name**
   ```
   Error: duplicate server name
   ```
   **Solution**: Remove duplicate proxy host

2. **Invalid directive**
   ```
   Error: unknown directive
   ```
   **Solution**: Check custom configuration for typos

3. **Missing semicolon**
   ```
   Error: unexpected "}"
   ```
   **Solution**: Add missing semicolon

---

### Nginx Won't Reload

**Symptom**: Configuration changes don't apply

**Check**:
```bash
# Check if Nginx process is running
docker exec infrapilot ps aux | grep nginx

# Try manual reload
docker exec infrapilot nginx -s reload

# Check for syntax errors
docker exec infrapilot nginx -t
```

**Solution**:
```bash
# Restart Nginx
docker exec infrapilot supervisorctl restart nginx

# If that fails, restart container
docker compose restart infrapilot
```

---

## Agent Issues

### Agent Offline

**Symptom**: Agent shows as "offline" in dashboard

**Check**:
```bash
# Check if agent process is running
docker exec infrapilot ps aux | grep agent

# Check agent logs
docker logs infrapilot | grep -i agent

# Check gRPC connection
docker exec infrapilot netstat -an | grep 9090
```

**Solution**:
```bash
# Restart agent service
docker exec infrapilot supervisorctl restart agent

# If that fails, restart container
docker compose restart infrapilot
```

---

### Agent Heartbeat Failed

**Symptom**: Agent connects but heartbeat fails

**Check**:
```bash
# Check network connectivity
docker exec infrapilot ping backend

# Check gRPC port
docker exec infrapilot telnet localhost 9090
```

**Solution**:
```bash
# Verify BACKEND_URL is correct
docker exec infrapilot env | grep BACKEND_URL

# Should be: localhost:9090 for single container

# Restart services
docker exec infrapilot supervisorctl restart agent
docker exec infrapilot supervisorctl restart backend
```

---

## Authentication Issues

### Cannot Login

**Symptom**: Login fails with correct credentials

**Check**:
```bash
# Check backend logs
docker logs infrapilot | grep -i auth

# Verify user exists
docker exec infrapilot psql -U infrapilot -c "SELECT email, role FROM users"
```

**Common causes**:

1. **Wrong password**

   **Solution**: Reset password via database
   ```bash
   # Generate new password hash
   docker exec infrapilot /usr/local/bin/hash-password "newpassword"

   # Update database
   docker exec infrapilot psql -U infrapilot -c "UPDATE users SET password_hash='hash' WHERE email='user@example.com'"
   ```

2. **Account locked**

   **Solution**: Unlock account
   ```bash
   docker exec infrapilot psql -U infrapilot -c "UPDATE users SET locked_until=NULL WHERE email='user@example.com'"
   ```

3. **MFA required but not set up**

   **Solution**: Disable MFA requirement temporarily
   ```bash
   MFA_REQUIRED=false
   ```

---

### JWT Token Invalid

**Symptom**: `Invalid token` error after login

**Check**:
```bash
# Verify JWT_SECRET hasn't changed
docker exec infrapilot env | grep JWT_SECRET

# Check token expiry
echo $JWT_EXPIRY
```

**Solution**:
```bash
# Ensure JWT_SECRET is consistent
# If changed, users need to re-login

# Logout and login again
```

---

### MFA Not Working

**Symptom**: MFA code rejected

**Check**:
```bash
# Verify system time is correct (critical for TOTP)
docker exec infrapilot date
timedatectl

# Time must be accurate within 30 seconds
```

**Solution**:
```bash
# Sync system time
sudo ntpdate pool.ntp.org

# Or use NTP daemon
sudo systemctl enable --now systemd-timesyncd
```

---

## Performance Issues

### Slow API Responses

**Symptom**: Requests take > 1 second

**Check**:
```bash
# Check CPU usage
docker stats infrapilot

# Check database query performance
docker exec infrapilot psql -U infrapilot -c "SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10"

# Check database connections
docker exec infrapilot psql -U infrapilot -c "SELECT count(*) FROM pg_stat_activity"
```

**Solution**:
```bash
# Increase container resources
docker update --cpus=4 --memory=4g infrapilot

# Add database indexes (if needed)
# Vacuum database
docker exec infrapilot psql -U infrapilot -c "VACUUM ANALYZE"

# Use external Redis for caching
REDIS_URL=redis://external-redis:6379
```

---

### High Memory Usage

**Symptom**: Container using > 4GB RAM

**Check**:
```bash
# Check memory usage breakdown
docker exec infrapilot ps aux --sort=-%mem | head

# Check database cache
docker exec infrapilot psql -U infrapilot -c "SELECT pg_size_pretty(pg_database_size('infrapilot'))"
```

**Solution**:
```bash
# Reduce connection pool size
DATABASE_URL="postgres://...?pool_max_conns=10"

# Reduce log retention
LOG_RETENTION_DAYS=7

# Use external databases
# They have their own memory management
```

---

### Database Queries Slow

**Symptom**: Queries taking > 1 second

**Check**:
```bash
# Enable query logging
docker exec infrapilot psql -U infrapilot -c "ALTER SYSTEM SET log_min_duration_statement = 1000"

# View slow queries
docker logs infrapilot | grep "duration:"

# Check missing indexes
docker exec infrapilot psql -U infrapilot -c "SELECT schemaname, tablename, attname, n_distinct, correlation FROM pg_stats WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY abs(correlation) DESC"
```

**Solution**:
```bash
# Add indexes (example)
docker exec infrapilot psql -U infrapilot -c "CREATE INDEX idx_logs_timestamp ON logs(created_at)"

# Vacuum and analyze
docker exec infrapilot psql -U infrapilot -c "VACUUM ANALYZE"
```

---

## Network Issues

### Cannot Access Dashboard

**Symptom**: Browser shows "Connection refused"

**Check**:
```bash
# Verify container is running
docker ps | grep infrapilot

# Check port mapping
docker port infrapilot

# Test from server
curl -I http://localhost

# Test from outside
curl -I http://your-server-ip
```

**Solution**:
```bash
# Check firewall
sudo ufw status
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Check iptables
sudo iptables -L -n -v | grep -E ':(80|443)'

# Restart container
docker compose restart infrapilot
```

---

### Containers Cannot Reach Internet

**Symptom**: Containers can't pull images or access external APIs

**Check**:
```bash
# Test from container
docker exec some-container ping 8.8.8.8
docker exec some-container curl https://google.com
```

**Solution**:
```bash
# Check Docker DNS
docker exec some-container cat /etc/resolv.conf

# Configure Docker DNS
# /etc/docker/daemon.json
{
  "dns": ["8.8.8.8", "8.8.4.4"]
}

sudo systemctl restart docker
```

---

## Logging Issues

### Logs Not Showing

**Symptom**: Container logs empty in UI

**Check**:
```bash
# Check if log collection is enabled
docker exec infrapilot ps aux | grep logstreamer

# Check database
docker exec infrapilot psql -U infrapilot -c "SELECT COUNT(*) FROM logs"
```

**Solution**:
```bash
# Restart log streamer
docker exec infrapilot supervisorctl restart logstreamer

# Check log retention settings
docker exec infrapilot env | grep LOG_RETENTION
```

---

### Logs Taking Too Much Space

**Symptom**: `/data` volume filling up with logs

**Check**:
```bash
# Check volume usage
docker system df -v

# Check log size
docker exec infrapilot du -sh /data/logs
docker exec infrapilot psql -U infrapilot -c "SELECT pg_size_pretty(pg_total_relation_size('logs'))"
```

**Solution**:
```bash
# Reduce retention
LOG_RETENTION_DAYS=7

# Manual cleanup
docker exec infrapilot psql -U infrapilot -c "DELETE FROM logs WHERE created_at < NOW() - INTERVAL '7 days'"
docker exec infrapilot psql -U infrapilot -c "VACUUM FULL logs"

# Set up automated cleanup
ENABLE_LOG_CLEANUP=true
```

---

## Upgrade Issues

### Upgrade Failed

**Symptom**: Container won't start after upgrade

**Solution**:
```bash
# Rollback to previous version
docker pull devsimplex/infrapilot:v1.0.0
docker compose up -d

# Check logs
docker logs infrapilot

# Try upgrade again after fixing issues
```

---

### Database Migration Failed During Upgrade

**Symptom**: Migration error in logs

**Solution**:
```bash
# Restore from backup
docker volume rm infrapilot_data
docker run --rm -v infrapilot_data:/data -v $(pwd):/backup alpine tar xzf /backup/backup.tar.gz -C /

# Retry upgrade
docker compose pull
docker compose up -d
```

---

## Data Issues

### Data Loss After Restart

**Symptom**: All configuration gone after restart

**Check**:
```bash
# Verify volume is mounted
docker inspect infrapilot | grep -A 10 Mounts

# Check volume exists
docker volume ls | grep infrapilot
```

**Solution**:
```bash
# Ensure volume is properly defined
# In docker-compose.yml:
volumes:
  infrapilot_data:

# And mounted:
volumes:
  - infrapilot_data:/data
```

---

### Cannot Restore Backup

**Symptom**: Restore fails or data corrupted

**Solution**:
```bash
# Stop container
docker compose stop infrapilot

# Remove existing volume
docker volume rm infrapilot_data

# Create new volume
docker volume create infrapilot_data

# Restore with correct paths
docker run --rm \
  -v infrapilot_data:/data \
  -v $(pwd):/backup \
  alpine sh -c "cd / && tar xzf /backup/backup.tar.gz"

# Start container
docker compose start infrapilot
```

---

## Getting Help

If you've tried these solutions and still have issues:

1. **Check GitHub Issues**: https://github.com/devsimplex-org/InfraPilot/issues
2. **Collect diagnostic info**:
   ```bash
   # System info
   uname -a
   docker version
   docker compose version

   # Container logs
   docker logs infrapilot > infrapilot.log

   # Configuration (remove secrets!)
   docker inspect infrapilot > infrapilot-inspect.json
   ```

3. **Create GitHub Issue** with:
   - InfraPilot version
   - Docker version
   - Operating system
   - Steps to reproduce
   - Relevant logs (no secrets!)

4. **Enterprise Support**: enterprise@infrapilot.org

---

**Last Updated**: 2026-01-14
