# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously at InfraPilot. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email us at **security@infrapilot.org** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Resolution Timeline:** Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Security Best Practices

When deploying InfraPilot:

1. **Change Default Credentials**
   - Update PostgreSQL password
   - Update Redis password
   - Generate a strong JWT secret: `openssl rand -base64 32`

2. **Use HTTPS in Production**
   - Configure Let's Encrypt email
   - Set `LETSENCRYPT_STAGING=false` for real certificates

3. **Secure Docker Socket**
   - The agent requires Docker socket access (read-only)
   - Ensure the host Docker daemon is properly secured

4. **Network Isolation**
   - Internal services use an isolated Docker network
   - Only nginx exposes ports to the host

5. **Keep Updated**
   - Regularly pull the latest images
   - Subscribe to security advisories

### Security Features

InfraPilot includes several security features:

- **No SSH Access:** All operations through Docker API
- **mTLS Agent Communication:** Encrypted gRPC between backend and agents
- **RBAC:** Role-based access control (super_admin, operator, viewer)
- **MFA Support:** TOTP-based two-factor authentication
- **Audit Logging:** Complete audit trail of all actions
- **Security Headers:** Automatic HSTS, X-Frame-Options, CSP support
- **Non-root Containers:** Backend and frontend run as non-root users
- **Read-only Filesystems:** Containers use read-only root filesystems where possible

## Acknowledgments

We appreciate the security research community and will acknowledge reporters in our release notes (with permission).
