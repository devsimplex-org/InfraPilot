package ssl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/go-acme/lego/v4/registration"
	"go.uber.org/zap"
)

// CertManager handles SSL certificate operations with Let's Encrypt
type CertManager struct {
	CertDir     string // Base directory for certificates (e.g., /etc/letsencrypt)
	WebRoot     string // Webroot directory for ACME HTTP-01 challenge (e.g., /var/www/acme-challenge)
	Email       string // Email for Let's Encrypt account
	Staging     bool   // Use staging server for testing
	logger      *zap.Logger
	accountFile string
}

// NewCertManager creates a new certificate manager
func NewCertManager(certDir, webRoot, email string, staging bool, logger *zap.Logger) *CertManager {
	return &CertManager{
		CertDir:     certDir,
		WebRoot:     webRoot,
		Email:       email,
		Staging:     staging,
		logger:      logger,
		accountFile: filepath.Join(certDir, "account.json"),
	}
}

// User implements the lego registration.User interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string                        { return u.Email }
func (u *User) GetRegistration() *registration.Resource { return u.Registration }
func (u *User) GetPrivateKey() crypto.PrivateKey        { return u.key }

// AccountData stores the account info on disk
type AccountData struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	KeyPEM       string                 `json:"key_pem"`
}

// RequestCertificate requests a new SSL certificate for the domain
func (m *CertManager) RequestCertificate(domain string) error {
	m.logger.Info("Requesting SSL certificate",
		zap.String("domain", domain),
		zap.Bool("staging", m.Staging),
	)

	// Get or create user
	user, err := m.getOrCreateUser()
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Create lego config
	config := lego.NewConfig(user)
	if m.Staging {
		config.CADirURL = lego.LEDirectoryStaging
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}
	config.Certificate.KeyType = certcrypto.RSA2048

	// Create client
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	// Use HTTP-01 challenge with webroot
	// Nginx will serve the challenge files from the webroot directory
	if m.WebRoot != "" {
		// Ensure webroot directory exists
		if err := os.MkdirAll(m.WebRoot, 0755); err != nil {
			return fmt.Errorf("failed to create webroot directory: %w", err)
		}

		provider, err := webroot.NewHTTPProvider(m.WebRoot)
		if err != nil {
			return fmt.Errorf("failed to create webroot provider: %w", err)
		}
		err = client.Challenge.SetHTTP01Provider(provider)
		if err != nil {
			return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
		}
	} else {
		// Fallback to standalone server (for backwards compatibility)
		err = client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
		if err != nil {
			return fmt.Errorf("failed to set HTTP-01 provider: %w", err)
		}
	}

	// Register if needed
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return fmt.Errorf("failed to register: %w", err)
		}
		user.Registration = reg

		// Save account
		if err := m.saveAccount(user); err != nil {
			m.logger.Warn("Failed to save account", zap.Error(err))
		}
	}

	// Request certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}

	// Save certificates
	if err := m.saveCertificate(domain, certificates); err != nil {
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	m.logger.Info("SSL certificate obtained successfully",
		zap.String("domain", domain),
	)

	return nil
}

// RenewCertificate renews an existing certificate
func (m *CertManager) RenewCertificate(domain string) error {
	m.logger.Info("Renewing SSL certificate", zap.String("domain", domain))

	// Check if certificate exists
	certPath := m.getCertPath(domain)
	if _, err := os.Stat(filepath.Join(certPath, "fullchain.pem")); os.IsNotExist(err) {
		return fmt.Errorf("certificate does not exist for domain: %s", domain)
	}

	// For renewal, we just request a new certificate
	return m.RequestCertificate(domain)
}

// GetCertificateExpiry returns the expiry date of a certificate
func (m *CertManager) GetCertificateExpiry(domain string) (time.Time, error) {
	certPath := filepath.Join(m.getCertPath(domain), "fullchain.pem")

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// NeedsRenewal checks if a certificate needs renewal (within 30 days of expiry)
func (m *CertManager) NeedsRenewal(domain string, daysBeforeExpiry int) (bool, error) {
	expiry, err := m.GetCertificateExpiry(domain)
	if err != nil {
		return false, err
	}

	renewalTime := expiry.AddDate(0, 0, -daysBeforeExpiry)
	return time.Now().After(renewalTime), nil
}

// CertificateExists checks if a certificate exists for a domain
func (m *CertManager) CertificateExists(domain string) bool {
	certPath := filepath.Join(m.getCertPath(domain), "fullchain.pem")
	_, err := os.Stat(certPath)
	return err == nil
}

// getCertPath returns the path for a domain's certificates
func (m *CertManager) getCertPath(domain string) string {
	return filepath.Join(m.CertDir, "live", domain)
}

// saveCertificate saves the certificate and key to disk
func (m *CertManager) saveCertificate(domain string, cert *certificate.Resource) error {
	certPath := m.getCertPath(domain)

	// Create directory
	if err := os.MkdirAll(certPath, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Save certificate chain
	fullchainPath := filepath.Join(certPath, "fullchain.pem")
	if err := os.WriteFile(fullchainPath, cert.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	privkeyPath := filepath.Join(certPath, "privkey.pem")
	if err := os.WriteFile(privkeyPath, cert.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Also save separate cert file (without chain)
	certOnlyPath := filepath.Join(certPath, "cert.pem")
	if err := os.WriteFile(certOnlyPath, cert.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}

	m.logger.Info("Saved certificate",
		zap.String("domain", domain),
		zap.String("path", certPath),
	)

	return nil
}

// getOrCreateUser gets or creates the ACME user
func (m *CertManager) getOrCreateUser() (*User, error) {
	// Try to load existing account
	user, err := m.loadAccount()
	if err == nil {
		return user, nil
	}

	m.logger.Info("Creating new ACME account", zap.String("email", m.Email))

	// Generate new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &User{
		Email: m.Email,
		key:   privateKey,
	}, nil
}

// loadAccount loads the ACME account from disk
func (m *CertManager) loadAccount() (*User, error) {
	data, err := os.ReadFile(m.accountFile)
	if err != nil {
		return nil, err
	}

	var account AccountData
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, err
	}

	// Parse private key
	block, _ := pem.Decode([]byte(account.KeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &User{
		Email:        account.Email,
		Registration: account.Registration,
		key:          key,
	}, nil
}

// saveAccount saves the ACME account to disk
func (m *CertManager) saveAccount(user *User) error {
	// Encode private key
	keyBytes, err := x509.MarshalECPrivateKey(user.key.(*ecdsa.PrivateKey))
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	account := AccountData{
		Email:        user.Email,
		Registration: user.Registration,
		KeyPEM:       string(keyPEM),
	}

	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal account: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(m.accountFile), 0700); err != nil {
		return fmt.Errorf("failed to create account directory: %w", err)
	}

	if err := os.WriteFile(m.accountFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write account file: %w", err)
	}

	m.logger.Info("Saved ACME account", zap.String("email", user.Email))
	return nil
}

// CertificateInfo contains information about a certificate
type CertificateInfo struct {
	Domain    string    `json:"domain"`
	Exists    bool      `json:"exists"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	DaysLeft  int       `json:"days_left,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	IsStaging bool      `json:"is_staging,omitempty"`
}

// GetCertificateInfo retrieves information about a domain's certificate
func (m *CertManager) GetCertificateInfo(domain string) (*CertificateInfo, error) {
	info := &CertificateInfo{
		Domain: domain,
		Exists: false,
	}

	if !m.CertificateExists(domain) {
		return info, nil
	}

	info.Exists = true

	// Read certificate
	certPath := filepath.Join(m.getCertPath(domain), "fullchain.pem")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return info, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Parse certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return info, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return info, fmt.Errorf("failed to parse certificate: %w", err)
	}

	info.ExpiresAt = cert.NotAfter
	info.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	info.Issuer = cert.Issuer.CommonName

	// Check if it's a staging certificate
	if cert.Issuer.Organization != nil && len(cert.Issuer.Organization) > 0 {
		for _, org := range cert.Issuer.Organization {
			if org == "(STAGING) Let's Encrypt" {
				info.IsStaging = true
				break
			}
		}
	}

	return info, nil
}
